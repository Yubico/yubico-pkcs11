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

//! `C_DigestInit`/`C_Digest`/`C_DigestUpdate`/`C_DigestFinal` hardware
//! coverage

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

/// `(mechanism, message, expected digest hex)` for each digest mechanism --
/// the expected digests are the standard NIST test vectors for the message
/// `b"abc"`, independently verified via Python's `hashlib` rather than
/// this crate's own `sha1`/`sha2` dependency, since those are
/// what's actually under test here.
fn digest_vectors() -> Vec<(CK_MECHANISM_TYPE, &'static [u8], &'static str)> {
    vec![
        (
            CKM_SHA_1 as CK_MECHANISM_TYPE,
            b"abc",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            CKM_SHA256 as CK_MECHANISM_TYPE,
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            CKM_SHA384 as CK_MECHANISM_TYPE,
            b"abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            CKM_SHA512 as CK_MECHANISM_TYPE,
            b"abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ]
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex literal in digest_vectors"))
        .collect()
}

/// No `token_init` or login -- digesting touches no PIV application state.
#[test]
fn test_digest() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_digest: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    for (mechanism, message, expected_hex) in digest_vectors() {
        let expected = hex_decode(expected_hex);

        // One-shot: C_DigestInit + C_Digest.
        let mut mechanism_struct = CK_MECHANISM {
            mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let rv = unsafe { ykcs11::C_DigestInit(session, &mut mechanism_struct) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DigestInit (one-shot, 0x{mechanism:x})");

        let mut digest = vec![0u8; expected.len()];
        let mut digest_len = digest.len() as CK_ULONG;
        let rv = unsafe {
            ykcs11::C_Digest(
                session,
                message.as_ptr() as CK_BYTE_PTR,
                message.len() as CK_ULONG,
                digest.as_mut_ptr(),
                &mut digest_len,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Digest (0x{mechanism:x})");
        assert_eq!(digest_len as usize, expected.len(), "C_Digest length (0x{mechanism:x})");
        assert_eq!(digest, expected, "C_Digest value (0x{mechanism:x})");

        // Streaming: C_DigestInit + two C_DigestUpdate calls + C_DigestFinal
        let rv = unsafe { ykcs11::C_DigestInit(session, &mut mechanism_struct) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DigestInit (streaming, 0x{mechanism:x})");

        let (first, rest) = message.split_at(1);
        let rv = unsafe {
            ykcs11::C_DigestUpdate(session, first.as_ptr() as CK_BYTE_PTR, first.len() as CK_ULONG)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DigestUpdate #1 (0x{mechanism:x})");
        let rv = unsafe {
            ykcs11::C_DigestUpdate(session, rest.as_ptr() as CK_BYTE_PTR, rest.len() as CK_ULONG)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DigestUpdate #2 (0x{mechanism:x})");

        let mut digest_streamed = vec![0u8; expected.len()];
        let mut digest_streamed_len = digest_streamed.len() as CK_ULONG;
        let rv = unsafe {
            ykcs11::C_DigestFinal(session, digest_streamed.as_mut_ptr(), &mut digest_streamed_len)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DigestFinal (0x{mechanism:x})");
        assert_eq!(
            digest_streamed_len as usize,
            expected.len(),
            "C_DigestFinal length (0x{mechanism:x})"
        );
        assert_eq!(digest_streamed, expected, "C_DigestFinal value (0x{mechanism:x})");
    }

    close_session(session);
}
