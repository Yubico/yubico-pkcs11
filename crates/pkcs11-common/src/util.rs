// Copyright 2026 Yubico AB

//! Small helpers shared by both modules.

/// Decode an ASCII hex string into raw bytes. `None` on odd length or any
/// non-hex-digit byte, matching the C modules' `hex_decode` (used for both
/// ykcs11's SO management-key login and yubihsm-pkcs11's auth key IDs).
pub fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}
