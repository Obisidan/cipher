//! WAV steganography: LSB embedding in WAV audio files.
//! Pure Rust, no external deps. Supports PCM WAV files.

use cipher_core::CipherError;

/// WAV file header markers
const RIFF_MARKER: &[u8; 4] = b"RIFF";
const WAVE_MARKER: &[u8; 4] = b"WAVE";
const FMT_MARKER: &[u8; 4] = b"fmt ";
const DATA_MARKER: &[u8; 4] = b"data";

/// A parsed WAV file.
pub struct WavFile {
    /// Raw file bytes
    pub data: Vec<u8>,
    /// Offset to audio sample data
    pub data_offset: usize,
    /// Size of audio sample data in bytes
    pub data_size: usize,
    /// Number of audio channels
    pub channels: u16,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bits per sample (8, 16, 24, or 32)
    pub bits_per_sample: u16,
    /// Bytes per sample
    pub bytes_per_sample: usize,
}

impl WavFile {
    /// Parse a WAV file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, CipherError> {
        if data.len() < 44 {
            return Err(CipherError::InvalidFormat);
        }

        // Check RIFF header
        if data[..4] != *RIFF_MARKER {
            return Err(CipherError::InvalidFormat);
        }
        if data[8..12] != *WAVE_MARKER {
            return Err(CipherError::InvalidFormat);
        }

        // Find fmt chunk
        let mut offset = 12;
        let mut found_fmt = false;
        let mut channels = 0u16;
        let mut sample_rate = 0u32;
        let mut bits_per_sample = 0u16;

        while offset + 8 <= data.len() {
            let chunk_id = &data[offset..offset + 4];
            let chunk_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if chunk_id == FMT_MARKER && offset + 24 <= data.len() {
                channels = u16::from_le_bytes([data[offset + 10], data[offset + 11]]);
                sample_rate = u32::from_le_bytes([
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ]);
                bits_per_sample = u16::from_le_bytes([data[offset + 22], data[offset + 23]]);
                found_fmt = true;
            }

            if chunk_id == DATA_MARKER {
                if !found_fmt {
                    return Err(CipherError::InvalidFormat);
                }

                let bytes_per_sample = (bits_per_sample / 8) as usize;

                return Ok(Self {
                    data: data.to_vec(),
                    data_offset: offset + 8,
                    data_size: chunk_size,
                    channels,
                    sample_rate,
                    bits_per_sample,
                    bytes_per_sample,
                });
            }

            // Move to next chunk (pad to even boundary)
            offset += 8 + chunk_size;
            if chunk_size % 2 != 0 {
                offset += 1;
            }
        }

        Err(CipherError::InvalidFormat)
    }

    /// Get a mutable slice of the audio sample data.
    pub fn sample_data_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.data_offset..self.data_offset + self.data_size]
    }

    /// Get an immutable slice of the audio sample data.
    pub fn sample_data(&self) -> &[u8] {
        &self.data[self.data_offset..self.data_offset + self.data_size]
    }

    /// Calculate the maximum payload capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.data_size / 8
    }

    /// Embed a payload into the WAV sample data using LSB.
    pub fn embed(&mut self, payload: &[u8]) -> Result<(), CipherError> {
        let capacity = self.capacity();
        if payload.len() + 4 > capacity {
            return Err(CipherError::CarrierTooSmall);
        }

        let samples = self.sample_data_mut();

        // Write 4-byte length header
        let len_bytes = (payload.len() as u32).to_be_bytes();
        for (i, &byte) in len_bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = i * 8 + bit_idx;
                if carrier_idx < samples.len() {
                    samples[carrier_idx] = (samples[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        // Embed payload
        for (i, &byte) in payload.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = (byte >> (7 - bit_idx)) & 1;
                let carrier_idx = 32 + i * 8 + bit_idx;
                if carrier_idx < samples.len() {
                    samples[carrier_idx] = (samples[carrier_idx] & 0xFE) | bit;
                }
            }
        }

        Ok(())
    }

    /// Extract a payload from the WAV sample data.
    pub fn extract(&self) -> Result<Vec<u8>, CipherError> {
        let samples = self.sample_data();

        if samples.len() < 32 {
            return Err(CipherError::InvalidFormat);
        }

        // Extract 4-byte length header
        let mut len_bytes = [0u8; 4];
        for i in 0..4 {
            for bit_idx in 0..8 {
                let carrier_idx = i * 8 + bit_idx;
                let bit = samples[carrier_idx] & 1;
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
                if carrier_idx >= samples.len() {
                    return Err(CipherError::InvalidFormat);
                }
                let bit = samples[carrier_idx] & 1;
                payload[i] |= bit << (7 - bit_idx);
            }
        }

        Ok(payload)
    }
}

/// Create a minimal valid PCM WAV file with silence.
pub fn create_test_wav(num_samples: usize, sample_rate: u32) -> Vec<u8> {
    let bits_per_sample: u16 = 16;
    let channels: u16 = 1;
    let bytes_per_sample = (bits_per_sample / 8) as usize;
    let data_size = num_samples * bytes_per_sample;
    let file_size = 44 + data_size;

    let mut data = Vec::with_capacity(file_size);

    // RIFF header
    data.extend_from_slice(b"RIFF");
    data.extend_from_slice(&((file_size - 8) as u32).to_le_bytes());
    data.extend_from_slice(b"WAVE");

    // fmt chunk
    data.extend_from_slice(b"fmt ");
    data.extend_from_slice(&16u32.to_le_bytes()); // Chunk size
    data.extend_from_slice(&1u16.to_le_bytes()); // Audio format (PCM)
    data.extend_from_slice(&channels.to_le_bytes());
    data.extend_from_slice(&sample_rate.to_le_bytes());
    let byte_rate = sample_rate * channels as u32 * bits_per_sample as u32 / 8;
    data.extend_from_slice(&byte_rate.to_le_bytes());
    let block_align = channels * bits_per_sample / 8;
    data.extend_from_slice(&block_align.to_le_bytes());
    data.extend_from_slice(&bits_per_sample.to_le_bytes());

    // data chunk
    data.extend_from_slice(b"data");
    data.extend_from_slice(&(data_size as u32).to_le_bytes());

    // Fill with sample data (sine wave-ish pattern for testing)
    for i in 0..num_samples {
        let sample = ((i as f64 * 0.1).sin() * 16000.0) as i16;
        data.extend_from_slice(&sample.to_le_bytes());
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wav_parse() {
        let wav_data = create_test_wav(1000, 44100);
        let wav = WavFile::parse(&wav_data).unwrap();
        assert_eq!(wav.sample_rate, 44100);
        assert_eq!(wav.channels, 1);
        assert_eq!(wav.bits_per_sample, 16);
    }

    #[test]
    fn test_wav_embed_extract() {
        let wav_data = create_test_wav(10000, 44100);
        let mut wav = WavFile::parse(&wav_data).unwrap();

        let payload = "Hello, WAV steganography!";
        wav.embed(payload.as_bytes()).unwrap();

        let extracted = wav.extract().unwrap();
        assert_eq!(extracted, payload.as_bytes());
    }

    #[test]
    fn test_wav_capacity() {
        let wav_data = create_test_wav(10000, 44100);
        let wav = WavFile::parse(&wav_data).unwrap();
        // 10000 samples * 2 bytes = 20000 bytes, / 8 = 2500 bytes capacity
        assert!(wav.capacity() >= 2500);
    }
}
