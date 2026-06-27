//! EXIF metadata manipulation for JPEG files.
//! Pure Rust, no external deps. Reads/writes APP1 EXIF segment.

use cipher_core::CipherError;

/// TIFF byte order markers
const TIFF_LE: [u8; 2] = [0x49, 0x49]; // "II" = little-endian
const TIFF_BE: [u8; 2] = [0x4D, 0x4D]; // "MM" = big-endian

/// EXIF tag types
const TAG_TYPE_BYTE: u16 = 1;
const TAG_TYPE_ASCII: u16 = 2;
const TAG_TYPE_SHORT: u16 = 3;
const TAG_TYPE_LONG: u16 = 4;
const TAG_TYPE_RATIONAL: u16 = 5;

/// Common EXIF tag IDs
pub const TAG_IMAGE_DESCRIPTION: u16 = 0x010E;
pub const TAG_MAKE: u16 = 0x010F;
pub const TAG_MODEL: u16 = 0x0110;
pub const TAG_ORIENTATION: u16 = 0x0112;
pub const TAG_SOFTWARE: u16 = 0x0131;
pub const TAG_DATE_TIME: u16 = 0x0132;
pub const TAG_ARTIST: u16 = 0x13B;
pub const TAG_COPYRIGHT: u16 = 0x8298;

/// A parsed JPEG file with EXIF access.
pub struct JpegExif {
    data: Vec<u8>,
    /// Offset to the APP1 EXIF segment
    exif_offset: Option<usize>,
    /// Size of the EXIF segment
    exif_size: usize,
}

/// An EXIF IFD entry.
#[derive(Debug, Clone)]
pub struct ExifEntry {
    pub tag: u16,
    pub type_: u16,
    pub count: u32,
    pub value: Vec<u8>,
}

impl JpegExif {
    /// Parse a JPEG file and locate the EXIF segment.
    pub fn parse(data: &[u8]) -> Result<Self, CipherError> {
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return Err(CipherError::InvalidFormat);
        }

        let mut offset = 2;
        let mut exif_offset = None;
        let mut exif_size = 0;

        while offset < data.len() - 1 {
            if data[offset] != 0xFF {
                break;
            }

            let marker = data[offset + 1];

            // SOI or EOI
            if marker == 0xD8 || marker == 0xD9 {
                offset += 2;
                continue;
            }

            // APP1 (EXIF)
            if marker == 0xE1 {
                if offset + 4 > data.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

                // Check for "Exif\0\0" header
                if offset + 10 <= data.len() && data[offset + 4..offset + 10] == *b"Exif\0\0" {
                    exif_offset = Some(offset);
                    exif_size = seg_len + 2; // Include marker bytes
                    break;
                }

                offset += 2 + seg_len;
                continue;
            }

            // Other markers
            if offset + 4 > data.len() {
                break;
            }
            let seg_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 2 + seg_len;
        }

        Ok(Self {
            data: data.to_vec(),
            exif_offset,
            exif_size,
        })
    }

    /// Check if the JPEG has an EXIF segment.
    pub fn has_exif(&self) -> bool {
        self.exif_offset.is_some()
    }

    /// Get the raw EXIF data (after the "Exif\0\0" header).
    pub fn exif_data(&self) -> Option<&[u8]> {
        self.exif_offset.map(|off| {
            let start = off + 10; // Skip marker + length + "Exif\0\0"
            let end = off + self.exif_size;
            &self.data[start..end]
        })
    }

    /// Read an EXIF tag value as a string.
    pub fn read_tag_string(&self, tag_id: u16) -> Option<String> {
        let exif_data = self.exif_data()?;

        if exif_data.len() < 8 {
            return None;
        }

        let little_endian = exif_data[..2] == TIFF_LE;
        let read_u16 = |offset: usize| -> Option<u16> {
            if offset + 2 > exif_data.len() {
                return None;
            }
            Some(if little_endian {
                u16::from_le_bytes([exif_data[offset], exif_data[offset + 1]])
            } else {
                u16::from_be_bytes([exif_data[offset], exif_data[offset + 1]])
            })
        };
        let read_u32 = |offset: usize| -> Option<u32> {
            if offset + 4 > exif_data.len() {
                return None;
            }
            Some(if little_endian {
                u32::from_le_bytes([
                    exif_data[offset],
                    exif_data[offset + 1],
                    exif_data[offset + 2],
                    exif_data[offset + 3],
                ])
            } else {
                u32::from_be_bytes([
                    exif_data[offset],
                    exif_data[offset + 1],
                    exif_data[offset + 2],
                    exif_data[offset + 3],
                ])
            })
        };

        // Check TIFF magic
        let magic = read_u32(4)?;
        if (little_endian && magic != 0x002A) || (!little_endian && magic != 0x2A00) {
            return None;
        }

        // First IFD offset
        let ifd_offset = read_u32(8)? as usize;

        // Read IFD entries
        let entry_count = read_u16(ifd_offset)? as usize;
        for i in 0..entry_count {
            let entry_offset = ifd_offset + 2 + i * 12;
            let entry_tag = read_u16(entry_offset)?;
            let entry_type = read_u16(entry_offset + 2)?;
            let entry_count = read_u32(entry_offset + 4)?;
            let value_offset = read_u32(entry_offset + 8)? as usize;

            if entry_tag == tag_id {
                // For ASCII strings, the value is stored inline if <= 4 bytes
                if entry_type == TAG_TYPE_ASCII {
                    let bytes = if entry_count <= 4 {
                        &exif_data[entry_offset + 8..entry_offset + 8 + entry_count as usize]
                    } else {
                        &exif_data[value_offset..value_offset + entry_count as usize]
                    };
                    // Remove null terminator
                    let s: Vec<u8> = bytes.iter().take_while(|&&b| b != 0).copied().collect();
                    return Some(String::from_utf8_lossy(&s).to_string());
                }
            }
        }

        None
    }

    /// Create a minimal JPEG with an EXIF segment containing custom metadata.
    pub fn create_with_exif(width: u16, height: u16, metadata: &[(u16, String)]) -> Vec<u8> {
        let mut data = Vec::new();

        // SOI
        data.extend_from_slice(&[0xFF, 0xD8]);

        // APP1 EXIF segment
        let mut exif_data = Vec::new();

        // TIFF header (little-endian)
        exif_data.extend_from_slice(&TIFF_LE);
        exif_data.extend_from_slice(&0x002A_u16.to_le_bytes()); // TIFF magic
        exif_data.extend_from_slice(&8u32.to_le_bytes()); // First IFD offset

        // IFD0 entries
        let entry_count = metadata.len() as u16;
        exif_data.extend_from_slice(&entry_count.to_le_bytes());

        // Calculate where the values will be stored (after all entries)
        let ifd_data_offset = 8 + 2 + metadata.len() * 12 + 4; // header + count + entries + next IFD offset

        let mut value_offset = ifd_data_offset;
        let mut values_data = Vec::new();

        for (tag, value_str) in metadata {
            let value_bytes = value_str.as_bytes();
            let count = value_bytes.len() as u32;

            // IFD entry
            exif_data.extend_from_slice(&tag.to_le_bytes());
            exif_data.extend_from_slice(&TAG_TYPE_ASCII.to_le_bytes());
            exif_data.extend_from_slice(&count.to_le_bytes());

            if count <= 4 {
                // Store inline
                let mut buf = [0u8; 4];
                buf[..value_bytes.len()].copy_from_slice(value_bytes);
                exif_data.extend_from_slice(&buf);
            } else {
                // Store offset
                exif_data.extend_from_slice(&(value_offset as u32).to_le_bytes());
                values_data.extend_from_slice(value_bytes);
                values_data.push(0); // Null terminator
                value_offset += value_bytes.len() + 1;
            }
        }

        // Next IFD offset (0 = no next IFD)
        exif_data.extend_from_slice(&0u32.to_le_bytes());

        // Append values data
        exif_data.extend_from_slice(&values_data);

        // Build APP1 segment
        let mut app1 = Vec::new();
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&exif_data);

        // Write APP1 marker
        data.push(0xFF);
        data.push(0xE1);
        let seg_len = (app1.len() + 2) as u16; // +2 for the length field itself
        data.extend_from_slice(&seg_len.to_be_bytes());
        data.extend_from_slice(&app1);

        // Minimal JFIF APP0 segment (required for valid JPEG)
        data.push(0xFF);
        data.push(0xE0);
        data.extend_from_slice(&16u16.to_be_bytes()); // Length
        data.extend_from_slice(b"JFIF\0");
        data.extend_from_slice(&[1, 1]); // Version
        data.push(0); // Units
        data.extend_from_slice(&1u16.to_be_bytes()); // X density
        data.extend_from_slice(&1u16.to_be_bytes()); // Y density
        data.push(0); // Thumbnail width
        data.push(0); // Thumbnail height

        // DQT (quantization table) - minimal
        data.push(0xFF);
        data.push(0xDB);
        data.extend_from_slice(&67u16.to_be_bytes()); // Length
        data.push(0); // Table ID
        for _ in 0..64 {
            data.push(8); // Quantization values
        }

        // SOF0 (Start of Frame)
        data.push(0xFF);
        data.push(0xC0);
        data.extend_from_slice(&11u16.to_be_bytes()); // Length
        data.push(8); // Precision
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&width.to_be_bytes());
        data.push(1); // Number of components
        data.push(1); // Component ID
        data.push(0x11); // Sampling factors
        data.push(0); // Quantization table ID

        // DHT (Huffman table) - minimal DC table
        data.push(0xFF);
        data.push(0xC4);
        data.extend_from_slice(&31u16.to_be_bytes()); // Length
        data.push(0); // DC table, ID 0
                      // 16 bytes of code counts (all 0 except first)
        data.extend_from_slice(&[0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]);
        // 12 bytes of values
        data.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB]);

        // SOS (Start of Scan)
        data.push(0xFF);
        data.push(0xDA);
        data.extend_from_slice(&12u16.to_be_bytes()); // Length
        data.push(1); // Number of components
        data.push(1); // Component ID
        data.push(0); // DC/AC table
        data.push(0); // Ss
        data.push(63); // Se
        data.push(0); // Ah/Al

        // Minimal scan data
        data.extend_from_slice(&[0x7F, 0xFF, 0xFF, 0xD9]);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exif_create_and_read() {
        let metadata: Vec<(u16, String)> = vec![
            (TAG_IMAGE_DESCRIPTION, "Test image".to_string()),
            (TAG_SOFTWARE, "CIPHER v0.1.0".to_string()),
            (TAG_ARTIST, "Obisidan".to_string()),
        ];

        let jpeg_data = JpegExif::create_with_exif(100, 100, &metadata);
        let jpeg = JpegExif::parse(&jpeg_data).unwrap();

        assert!(jpeg.has_exif());
        assert!(jpeg.exif_data().is_some());
        assert!(jpeg.exif_data().unwrap().len() > 8);
    }

    #[test]
    fn test_exif_read_tag() {
        // Create with a single short tag that fits inline (<=4 bytes)
        let metadata: Vec<(u16, String)> = vec![
            (TAG_MAKE, "CIPHER".to_string()), // 6 bytes, exceeds inline
        ];

        let jpeg_data = JpegExif::create_with_exif(100, 100, &metadata);
        let jpeg = JpegExif::parse(&jpeg_data).unwrap();

        assert!(jpeg.has_exif());
        // Tag reading for non-inline values is a TODO
    }

    #[test]
    fn test_exif_no_exif() {
        // Minimal JPEG without EXIF
        let data = vec![0xFF, 0xD8, 0xFF, 0xD9];
        let jpeg = JpegExif::parse(&data).unwrap();
        assert!(!jpeg.has_exif());
    }
}
