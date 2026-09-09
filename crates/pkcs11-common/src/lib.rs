//! Shared utilities used by both yubihsm-pkcs11 and ykcs11.

pub mod backend;
pub mod debug;
pub mod function_list;
pub mod session;
pub mod stubs;

/// Pad a byte array with spaces (PKCS#11 convention — not null-terminated).
pub fn str_pad(dst: &mut [u8], src: &str) {
    let src_bytes = src.as_bytes();
    let len = src_bytes.len().min(dst.len());
    dst[..len].copy_from_slice(&src_bytes[..len]);
    dst[len..].fill(b' ');
}