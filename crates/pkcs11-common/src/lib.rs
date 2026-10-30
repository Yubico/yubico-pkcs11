/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod backend;
pub mod debug;
pub mod decrypt;
pub mod digest;
pub mod encrypt;
pub mod function_list;
pub mod mechanism;
pub mod session;
pub mod sign;
pub mod stubs;
pub mod verify;
pub mod util;
#[cfg(windows)]
mod win_dllmain;

/// Pad a byte array with spaces (PKCS#11 convention — not null-terminated).
pub fn str_pad(dst: &mut [u8], src: &str) {
    let src_bytes = src.as_bytes();
    let len = src_bytes.len().min(dst.len());
    dst[..len].copy_from_slice(&src_bytes[..len]);
    dst[len..].fill(b' ');
}