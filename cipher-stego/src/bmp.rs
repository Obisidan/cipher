//! BMP steganography: LSB embedding in BMP image files.
//! Pure Rust, no external deps. Supports 24-bit and 32-bit BMP.

use cipher_core::CipherError;

/// BMP file header (14 bytes)
const BMP_SIGNATURE: [u8; 2] = [0x42, 0x4D]; // "BM"

/// A parsed BMP file.
pub struct BmpFile {
    /// Raw file bytes
    pub data: Vec<u8>,
    /// Offset to pixel data
    pub pixel_offset: u32,
    /// Image width in pixels
    pub width: i32,
    /// Image height in pixels (negative = top-down)
    pub height: i32,
    /// Bits per pixel (24 or 32)
    pub bpp: u16,
    /// Row size in bytes (including padding)
    pub row_size: usize,
    /// Number of bytes per pixel
    pub bytes_per_pixel: usize,
}

impl BmpFile {
    /// Parse a BMP file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, CipherError> {
        if data.len() < 54 {
            return Err(CipherError::InvalidFormat);
        }

        if data[..2] != BMP_SIGNATURE {
            return Err(CipherError::InvalidFormat);
        }

        let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        let height = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
        let bpp = u16::from_le_bytes([data[28], data[29]]);

        let bytes_per_pixel = match bpp {
            24 => 3,
            32 => 4,
            _ => return Err(CipherError::InvalidFormat),
        };

        // Rows are padded to 4-byte boundaries
        let row_size = ((bpp as usize * width as usize + 31) / 32) * 4;

        Ok(Self {
            data: data.to_vec(),
            pixel_offset,
            width,
            height,
            bpp,
            row_size,
            bytes_per_pixel,
        })
    }

    /// Get a mutable slice of the pixel data.
    pub fn pixel_data_mut(&mut self) -> &mut [u8] {
        let start = self.pixel_offset as usize;
        let height = self.height.abs() as usize;
        let total_size = self.row_size * height;
        &mut self.data[start..start + total_size]
    }

    /// Get an immutable slice of the pixel data.
    pub fn pixel_data(&self) -> &[u8] {
        let start = self.pixel_offset as usize;
        let height = self.height.abs() as usize;
        let total_size = self.row_size * height;
        &self.data[start..start + total_size]
    }

    /// Calculate the maximum payload capacity in bytes.
    pub fn capacity(&self) -> usize {
        let total_pixel_bytes =
            self.width.abs() as usize * self.height.abs() as usize * self.bytes_per_pixel;
        total_pixel_bytes / 8
    }

    /// Embed a payload into the BMP pixel data using LSB.
    pub fn embed(&mut self, payload: &[u8]) -> Result<(), CipherError> {
        let capacity = self.capacity();
        if payload.len() + 4 > capacity {
            return Err(CipherError::CarrierTooSmall);
        }

        let pixels = self.pixel_data_mut();

        // Write 4-byte length header
        let len_bytes = (payload.len() as u32).to_be_bytes();
        for (i, &byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = i * 8 + bit_idx;
                if carrier_idx < pixels.len() {
                    pixels[carrier_idx] = (pixels[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        // Embed payload
        for (i, &byte) in payload.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = 32 + i * 8 + bit_idx;
                if carrier_idx < pixels.len() {
                    pixels[carrier_idx] = (pixels[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        Ok(())
    }

    /// Extract a payload from the BMP pixel data.
    pub fn extract(&self) -> Result<Vec<u8>, CipherError> {
        let pixels = self.pixel_data();

        if pixels.len() < 32 {
            return Err(CipherError::InvalidFormat);
        }

        // Extract 4-byte length header
        let mut len_bytes = [0u8; 4];
        for i in 0..4 {
            for bit_idx in 0..8 {
                let carrier_idx = i * 8 + bit_idx;
                let bit = pixels[carrier_idx] & 1;
                len_bytes[i] |= bit << (7 - bit_idx);
            }
        }
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        if payload_len == 0 || payload_len > self.capacity() {
            return Err(CipherError::InvalidFormat);
        }

        // Extract payload
        let mut payload = vec![0u8; payload_len];
        for i in 0..payload_len {
            for bit_idx in 0..8 {
                let carrier_idx = 32 + i * 8 + bit_idx;
                if carrier_idx >= pixels.len() {
                    return Err(CipherError::InvalidFormat);
                }
                let bit = pixels[carrier_idx] & 1;
                payload[i] |= bit << (7 - bit_idx);
            }
        }

        Ok(payload)
    }
}

/// Create a minimal valid 24-bit BMP file with a solid color.
pub fn create_test_bmp(width: u32, height: u32, color: [u8; 3]) -> Vec<u8> {
    let bytes_per_pixel = 3;
    let row_size = ((24 * width as usize + 31) / 32) * 4;
    let pixel_data_size = row_size * height as usize;
    let file_size = 54 + pixel_data_size;

    let mut data = Vec::with_capacity(file_size);

    // BMP file header (14 bytes)
    data.extend_from_slice(b"BM"); // Signature
    data.extend_from_slice(&(file_size as u32).to_le_bytes()); // File size
    data.extend_from_slice(&[0, 0, 0, 0]); // Reserved
    data.extend_from_slice(&54u32.to_le_bytes()); // Pixel data offset

    // DIB header (40 bytes) - BITMAPINFOHEADER
    data.extend_from_slice(&40u32.to_le_bytes()); // Header size
    data.extend_from_slice(&(width as i32).to_le_bytes()); // Width
    data.extend_from_slice(&(height as i32).to_le_bytes()); // Height
    data.extend_from_slice(&1u16.to_le_bytes()); // Color planes
    data.extend_from_slice(&24u16.to_le_bytes()); // Bits per pixel
    data.extend_from_slice(&0u32.to_le_bytes()); // Compression (none)
    data.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // Image size
    data.extend_from_slice(&2835i32.to_le_bytes()); // Horizontal resolution (72 DPI)
    data.extend_from_slice(&2835i32.to_le_bytes()); // Vertical resolution (72 DPI)
    data.extend_from_slice(&0u32.to_le_bytes()); // Colors in palette
    data.extend_from_slice(&0u32.to_le_bytes()); // Important colors

    // Pixel data (bottom-up, BGR format, rows padded to 4 bytes)
    for _ in 0..height {
        for _ in 0..width {
            data.push(color[2]); // B
            data.push(color[1]); // G
            data.push(color[0]); // R
        }
        // Pad row to 4-byte boundary
        let padding = row_size - width as usize * bytes_per_pixel;
        for _ in 0..padding {
            data.push(0);
        }
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmp_parse() {
        let bmp_data = create_test_bmp(10, 10, [255, 0, 0]);
        let bmp = BmpFile::parse(&bmp_data).unwrap();
        assert_eq!(bmp.width, 10);
        assert_eq!(bmp.height, 10);
        assert_eq!(bmp.bpp, 24);
    }

    #[test]
    fn test_bmp_embed_extract() {
        let bmp_data = create_test_bmp(100, 100, [128, 64, 32]);
        let mut bmp = BmpFile::parse(&bmp_data).unwrap();

        let payload = b"Hello, BMP steganography!";
        bmp.embed(payload).unwrap();

        let extracted = bmp.extract().unwrap();
        assert_eq!(extracted, payload.to_vec());
    }

    #[test]
    fn test_bmp_capacity() {
        let bmp_data = create_test_bmp(100, 100, [128, 64, 32]);
        let bmp = BmpFile::parse(&bmp_data).unwrap();
        // 100*100*3 = 30000 bytes, / 8 = 3750 bytes capacity
        assert!(bmp.capacity() >= 3750);
    }
}
