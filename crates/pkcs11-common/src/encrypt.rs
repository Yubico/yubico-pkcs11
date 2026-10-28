/*
 * Copyright (c) 2026 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


use crate::digest::DigestOp;
use crate::sign::{mgf1, zero_pad};
use crate::verify::rsa_public_raw_op;
use pkcs11_sys::*;

/// `CKM_RSA_X_509` encrypt: no padding beyond left-zero-padding the message
/// to `modulus_len`, then the raw RSA public-key operation.
pub fn rsa_x509_encrypt(n: &[u8], e: &[u8], modulus_len: usize, message: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let padded = zero_pad(message, modulus_len)?;
    rsa_public_raw_op(n, e, &padded, modulus_len)
}

/// EME-PKCS1-v1_5-ENCODE (RFC 8017 §7.2.1): `0x00 0x02 || PS || 0x00 || M`,
/// where `PS` is exactly `modulus_len - message.len() - 3` non-zero random
/// bytes supplied by the caller (`ps.len()` must already be that exact
/// count — this function only assembles the block and validates shape, it
/// doesn't draw or filter randomness itself).
fn eme_pkcs1_v15_encode(message: &[u8], ps: &[u8], modulus_len: usize) -> Result<Vec<u8>, CK_RV> {
    if message.len() + 11 > modulus_len {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    if ps.len() != modulus_len - message.len() - 3 || ps.iter().any(|&b| b == 0) {
        // Caller-side invariant violation (wrong PS length, or forgot to
        // filter out zero bytes), not a PKCS#11-caller-facing error.
        return Err(CKR_GENERAL_ERROR.into());
    }
    let mut em = Vec::with_capacity(modulus_len);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(ps);
    em.push(0x00);
    em.extend_from_slice(message);
    Ok(em)
}

/// `CKM_RSA_PKCS` encrypt: `eme_pkcs1_v15_encode` then the raw RSA
/// public-key operation.
pub fn rsa_pkcs1_encrypt(
    n: &[u8],
    e: &[u8],
    modulus_len: usize,
    message: &[u8],
    ps: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let em = eme_pkcs1_v15_encode(message, ps, modulus_len)?;
    rsa_public_raw_op(n, e, &em, modulus_len)
}

/// EME-OAEP-ENCODE (RFC 8017 §7.1.1): the inverse of `decrypt.rs`'s
/// `eme_oaep_unpad`. `seed` must be exactly `hLen` (the hash's output size)
/// random bytes, supplied by the caller.
fn eme_oaep_encode(
    message: &[u8],
    label: &[u8],
    seed: &[u8],
    modulus_len: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let mut l_hasher = DigestOp::new(hash_mechanism)?;
    l_hasher.update(label);
    let l_hash = l_hasher.finalize();
    let h_len = l_hash.len();

    if seed.len() != h_len {
        return Err(CKR_GENERAL_ERROR.into());
    }
    if modulus_len < 2 * h_len + 2 || message.len() > modulus_len - 2 * h_len - 2 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }

    let ps_len = modulus_len - message.len() - 2 * h_len - 2;
    let mut db = l_hash;
    db.extend(std::iter::repeat(0u8).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(message);

    let db_mask = mgf1(seed, db.len(), mgf_hash_mechanism)?;
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let seed_mask = mgf1(&masked_db, h_len, mgf_hash_mechanism)?;
    let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let mut em = Vec::with_capacity(modulus_len);
    em.push(0x00);
    em.extend(masked_seed);
    em.extend(masked_db);
    Ok(em)
}

/// `CKM_RSA_PKCS_OAEP` encrypt: `eme_oaep_encode` then the raw RSA
/// public-key operation.
#[allow(clippy::too_many_arguments)]
pub fn rsa_oaep_encrypt(
    n: &[u8],
    e: &[u8],
    modulus_len: usize,
    message: &[u8],
    label: &[u8],
    seed: &[u8],
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let em = eme_oaep_encode(message, label, seed, modulus_len, hash_mechanism, mgf_hash_mechanism)?;
    rsa_public_raw_op(n, e, &em, modulus_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::{eme_oaep_unpad, eme_pkcs1_v15_unpad};

    #[test]
    fn eme_pkcs1_v15_encode_then_unpad_round_trips() {
        let ps = vec![0xAAu8; 256 - 11 - 3];
        let em = eme_pkcs1_v15_encode(b"hello world", &ps, 256).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(eme_pkcs1_v15_unpad(&em).unwrap(), b"hello world");
    }

    #[test]
    fn eme_pkcs1_v15_encode_rejects_message_too_long() {
        let message = vec![0u8; 250];
        let ps = vec![0xAAu8; 3];
        assert!(eme_pkcs1_v15_encode(&message, &ps, 256).is_err());
    }

    #[test]
    fn eme_pkcs1_v15_encode_rejects_zero_byte_in_ps() {
        let mut ps = vec![0xAAu8; 256 - 11 - 3];
        ps[0] = 0x00;
        assert!(eme_pkcs1_v15_encode(b"hello world", &ps, 256).is_err());
    }

    #[test]
    fn eme_oaep_encode_then_unpad_round_trips() {
        let seed = vec![0x42u8; 32];
        let em = eme_oaep_encode(
            b"the quick brown fox",
            b"",
            &seed,
            256,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        assert_eq!(em.len(), 256);
        let recovered = eme_oaep_unpad(
            &em,
            b"",
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        assert_eq!(recovered, b"the quick brown fox");
    }

    #[test]
    fn eme_oaep_encode_rejects_message_too_long() {
        let seed = vec![0x42u8; 32];
        let message = vec![0u8; 256 - 2 * 32 - 1];
        assert!(
            eme_oaep_encode(
                &message,
                b"",
                &seed,
                256,
                CKM_SHA256 as CK_MECHANISM_TYPE,
                CKM_SHA256 as CK_MECHANISM_TYPE,
            )
            .is_err()
        );
    }

    // 2048-bit RSA test key, same one `verify.rs`'s tests use.
    include!("verify_test_key.rs");

    fn modexp(input: &[u8], exp: &[u8]) -> Vec<u8> {
        let base = rsa::BigUint::from_bytes_be(input);
        let e = rsa::BigUint::from_bytes_be(exp);
        let n = rsa::BigUint::from_bytes_be(TEST_RSA_N);
        base.modpow(&e, &n).to_bytes_be()
    }

    #[test]
    fn rsa_x509_encrypt_then_decrypt_round_trips() {
        let message = [0x22u8; 256];
        let ct = rsa_x509_encrypt(TEST_RSA_N, TEST_RSA_E, 256, &message).unwrap();
        let pt = zero_pad(&modexp(&ct, TEST_RSA_D), 256).unwrap();
        assert_eq!(pt, message);
    }

    #[test]
    fn rsa_pkcs1_encrypt_then_decrypt_round_trips() {
        let ps = vec![0xAAu8; 256 - 11 - 3];
        let ct = rsa_pkcs1_encrypt(TEST_RSA_N, TEST_RSA_E, 256, b"hello world", &ps).unwrap();
        let em = zero_pad(&modexp(&ct, TEST_RSA_D), 256).unwrap();
        assert_eq!(eme_pkcs1_v15_unpad(&em).unwrap(), b"hello world");
    }

    #[test]
    fn rsa_oaep_encrypt_then_decrypt_round_trips() {
        let seed = vec![0x42u8; 32];
        let ct = rsa_oaep_encrypt(
            TEST_RSA_N,
            TEST_RSA_E,
            256,
            b"the quick brown fox",
            b"",
            &seed,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        let em = zero_pad(&modexp(&ct, TEST_RSA_D), 256).unwrap();
        let pt = eme_oaep_unpad(
            &em,
            b"",
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        assert_eq!(pt, b"the quick brown fox");
    }
}
