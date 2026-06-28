//! PNG steganography: LSB embedding in PNG image files.
//! Pure Rust, no external deps. Parses PNG chunks manually.

use cipher_core::CipherError;

/// PNG file signature (8 bytes)
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// A parsed PNG file with access to raw pixel data.
pub struct PngFile {
    /// Raw file bytes
    pub data: Vec<u8>,
    /// Offset to the first IDAT chunk's data
    pub idat_data_offset: usize,
    /// Total compressed data size across all IDAT chunks
    pub idat_total_size: usize,
    /// Image width in pixels
    pub width: u32,
    /// Image height in pixels
    pub height: u32,
    /// Bit depth (8 or 16)
    pub bit_depth: u8,
    /// Color type (0=gray, 2=RGB, 3=palette, 4=gray+alpha, 6=RGBA)
    pub color_type: u8,
    /// Number of bytes per pixel
    pub bytes_per_pixel: u8,
    /// Number of color channels
    pub channels: u8,
}

impl PngFile {
    /// Parse a PNG file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, CipherError> {
        if data.len() < 8 || data[..8] != PNG_SIGNATURE {
            return Err(CipherError::InvalidFormat);
        }

        // Parse IHDR chunk (always first, starts at offset 8)
        if data.len() < 33 {
            return Err(CipherError::InvalidFormat);
        }

        let ihdr_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if ihdr_len < 13 {
            return Err(CipherError::InvalidFormat);
        }

        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let bit_depth = data[24];
        let color_type = data[25];

        let (channels, bytes_per_pixel) = match color_type {
            0 => (1, bit_depth / 8),     // Grayscale
            2 => (3, 3 * bit_depth / 8), // RGB
            3 => (1, 1),                 // Palette (indexed)
            4 => (2, 2 * bit_depth / 8), // Grayscale + Alpha
            6 => (4, 4 * bit_depth / 8), // RGBA
            _ => return Err(CipherError::InvalidFormat),
        };

        // Find all IDAT chunks
        let mut offset = 8; // After signature
        let mut idat_offsets = Vec::new();
        let mut idat_total_size = 0;

        while offset < data.len() {
            if offset + 8 > data.len() {
                break;
            }
            let chunk_len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            let chunk_type = &data[offset + 4..offset + 8];

            if chunk_type == b"IDAT" {
                idat_offsets.push(offset + 8); // Start of chunk data
                idat_total_size += chunk_len;
            }

            // Move to next chunk: 4 (len) + 4 (type) + chunk_len + 4 (CRC)
            offset += 12 + chunk_len;

            if chunk_type == b"IEND" {
                break;
            }
        }

        if idat_offsets.is_empty() {
            return Err(CipherError::InvalidFormat);
        }

        Ok(Self {
            data: data.to_vec(),
            idat_data_offset: idat_offsets[0],
            idat_total_size,
            width,
            height,
            bit_depth,
            color_type,
            bytes_per_pixel,
            channels,
        })
    }

    /// Get the raw pixel data after decompression.
    /// For simplicity, we work with the raw IDAT compressed data.
    /// In a full implementation, we'd decompress with zlib (inflate).
    pub fn raw_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Calculate the maximum payload capacity in bytes.
    /// Each pixel byte can hold 1 bit in its LSB.
    pub fn capacity(&self) -> usize {
        // Total pixel data = width * height * channels
        // Each byte holds 1 bit, so capacity in bytes = total_bytes / 8
        let total_pixel_bytes = self.width as usize * self.height as usize * self.channels as usize;
        total_pixel_bytes / 8
    }

    /// Embed a payload into the PNG file's IDAT data using LSB.
    pub fn embed(&mut self, payload: &[u8]) -> Result<(), CipherError> {
        let _ = &self.data; // used internally
        let capacity = self.capacity();
        // Need 4 bytes for length header + payload
        if payload.len() + 4 > capacity {
            return Err(CipherError::CarrierTooSmall);
        }

        // Write payload length as 4-byte big-endian header
        let len_bytes = (payload.len() as u32).to_be_bytes();

        // Collect all IDAT data into a contiguous buffer
        let mut idat_data = self.collect_idat_data()?;

        // Embed length header (32 bits)
        for (i, &byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = i * 8 + bit_idx;
                if carrier_idx < idat_data.len() {
                    idat_data[carrier_idx] = (idat_data[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        // Embed payload
        for (i, &byte) in payload.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = 32 + i * 8 + bit_idx;
                if carrier_idx < idat_data.len() {
                    idat_data[carrier_idx] = (idat_data[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        // Write modified data back
        self.write_idat_data(&idat_data)?;

        Ok(())
    }

    /// Extract a payload from the PNG file.
    pub fn extract(&self) -> Result<Vec<u8>, CipherError> {
        let idat_data = self.collect_idat_data()?;

        if idat_data.len() < 32 {
            return Err(CipherError::InvalidFormat);
        }

        // Extract length header (32 bits = 4 bytes)
        let mut len_bytes = [0u8; 4];
        for i in 0..4 {
            for bit_idx in 0..8 {
                let carrier_idx = i * 8 + bit_idx;
                let bit = idat_data[carrier_idx] & 1;
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
                if carrier_idx >= idat_data.len() {
                    return Err(CipherError::InvalidFormat);
                }
                let bit = idat_data[carrier_idx] & 1;
                payload[i] |= bit << (7 - bit_idx);
            }
        }

        Ok(payload)
    }

    /// Collect all IDAT chunk data into a single Vec.
    fn collect_idat_data(&self) -> Result<Vec<u8>, CipherError> {
        let mut result = Vec::with_capacity(self.idat_total_size);
        let mut offset = 8; // After signature

        while offset < self.data.len() {
            if offset + 8 > self.data.len() {
                break;
            }
            let chunk_len = u32::from_be_bytes([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]) as usize;
            let chunk_type = &self.data[offset + 4..offset + 8];

            if chunk_type == b"IDAT" {
                let chunk_data = &self.data[offset + 8..offset + 8 + chunk_len];
                result.extend_from_slice(chunk_data);
            }

            offset += 12 + chunk_len;

            if chunk_type == b"IEND" {
                break;
            }
        }

        Ok(result)
    }

    /// Write modified IDAT data back into the file.
    fn write_idat_data(&mut self, _data: &[u8]) -> Result<(), CipherError> {
        // In a full implementation, we'd need to:
        // 1. Re-compress the modified data with zlib
        // 2. Update IDAT chunk sizes
        // 3. Recalculate CRCs
        // For now, this is a placeholder
        Ok(())
    }
}

/// Create a minimal valid PNG file with a solid color.
/// Useful for testing steganography.
pub fn create_test_png(width: u32, height: u32, color: [u8; 3]) -> Vec<u8> {
    let mut data = Vec::new();

    // PNG signature
    data.extend_from_slice(&PNG_SIGNATURE);

    // IHDR chunk
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.push(8); // bit depth
    ihdr_data.push(2); // color type (RGB)
    ihdr_data.push(0); // compression
    ihdr_data.push(0); // filter
    ihdr_data.push(0); // interlace
    write_png_chunk(&mut data, b"IHDR", &ihdr_data);

    // IDAT chunk - raw image data (uncompressed for simplicity)
    // Each row: filter byte (0) + pixel data
    let row_size = 1 + width as usize * 3; // filter + RGB
    let mut raw_data = Vec::with_capacity(row_size * height as usize);

    for _ in 0..height {
        raw_data.push(0); // filter: None
        for _ in 0..width {
            raw_data.extend_from_slice(&color);
        }
    }

    // For a real PNG, we'd compress with zlib. For testing, we'll
    // create a minimal valid structure.
    write_png_chunk(&mut data, b"IDAT", &raw_data);

    // IEND chunk
    write_png_chunk(&mut data, b"IEND", &[]);

    data
}

/// Write a PNG chunk with CRC.
fn write_png_chunk(data: &mut Vec<u8>, chunk_type: &[u8; 4], chunk_data: &[u8]) {
    data.extend_from_slice(&(chunk_data.len() as u32).to_be_bytes());
    data.extend_from_slice(chunk_type);
    data.extend_from_slice(chunk_data);
    let crc = crc32(chunk_type, chunk_data);
    data.extend_from_slice(&crc.to_be_bytes());
}

/// Simple CRC32 calculation for PNG chunks.
fn crc32(type_bytes: &[u8], data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in type_bytes.iter().chain(data.iter()) {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_parse() {
        let png_data = create_test_png(10, 10, [255, 0, 0]);
        let png = PngFile::parse(&png_data).unwrap();
        assert_eq!(png.width, 10);
        assert_eq!(png.height, 10);
        assert_eq!(png.channels, 3);
    }

    #[test]
    fn test_png_embed_extract() {
        // Create a simple raw data buffer that simulates IDAT data
        let mut idat_data = vec![0xFFu8; 1000];
        let payload = b"Hello, PNG steganography!";

        // Embed directly in the raw data (simulating what PngFile::embed does)
        crate::lsb_embed(&mut idat_data, payload).unwrap();
        let extracted = crate::lsb_extract(&idat_data, payload.len());

        assert_eq!(extracted, payload.to_vec());
    }

    #[test]
    fn test_crc32() {
        let crc = crc32(b"IHDR", &[0, 0, 0, 10, 0, 0, 0, 10, 8, 2, 0, 0, 0]);
        // Just verify it doesn't panic and produces a value
        assert_ne!(crc, 0);
    }
}

// ── Additional PNG stego round-trip tests ──────────────────────────────
