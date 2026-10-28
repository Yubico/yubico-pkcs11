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
use crate::sign::mgf1;
use pkcs11_sys::*;

/// `CKM_RSA_PKCS` decrypt: EME-PKCS1-v1_5-DECODE. `em` is the raw RSA
/// private-key operation's output (exactly `modulus_len` bytes once
/// zero-padded — matches `decrypt_mechanism_final`'s raw `ykpiv_decipher_data`
/// call followed by `RSA_padding_check_PKCS1_type_2`, mechanisms.c:737-750).
pub fn eme_pkcs1_v15_unpad(em: &[u8]) -> Result<Vec<u8>, CK_RV> {
    // RFC 8017 step 3: EM = 0x00 || 0x02 || PS || 0x00 || M, with PS at
    // least 8 bytes of non-zero padding — so a valid EM is at least 11
    // bytes, and the first two bytes are fixed.
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x02 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    let Some(sep) = em[2..].iter().position(|&b| b == 0x00) else {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    };
    if sep < 8 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    Ok(em[2 + sep + 1..].to_vec())
}

/// `CKM_RSA_PKCS_OAEP` decrypt: EME-OAEP-DECODE. `em` is the raw RSA
/// private-key operation's output, zero-padded to `modulus_len` bytes —
/// matches `RSA_padding_check_PKCS1_OAEP_mgf1` (mechanisms.c:752-754).
/// `label` is the (possibly empty) `CKZ_DATA_SPECIFIED` source data from the
/// mechanism's `CK_RSA_PKCS_OAEP_PARAMS`.
pub fn eme_oaep_unpad(
    em: &[u8],
    label: &[u8],
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let mut l_hasher = DigestOp::new(hash_mechanism)?;
    l_hasher.update(label);
    let l_hash = l_hasher.finalize();
    let h_len = l_hash.len();
    let modulus_len = em.len();

    // RFC 8017 step 1(b)/(c): k must be at least 2*hLen + 2, and Y (the
    // leading byte) must be zero.
    if modulus_len < 2 * h_len + 2 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }

    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];

    let seed_mask = mgf1(masked_db, h_len, mgf_hash_mechanism)?;
    let seed: Vec<u8> = masked_seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let db_mask = mgf1(&seed, masked_db.len(), mgf_hash_mechanism)?;
    let db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // DB = lHash' || PS || 0x01 || M.
    let (db_lhash, rest) = db.split_at(h_len);
    let Some(sep) = rest.iter().position(|&b| b == 0x01) else {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    };
    if em[0] != 0x00 || db_lhash != l_hash.as_slice() || rest[..sep].iter().any(|&b| b != 0) {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }

    Ok(rest[sep + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkcs1_v15_pad(message: &[u8], modulus_len: usize) -> Vec<u8> {
        let ps_len = modulus_len - message.len() - 3;
        let mut em = vec![0x00, 0x02];
        em.extend(std::iter::repeat(0xFFu8).take(ps_len));
        em.push(0x00);
        em.extend_from_slice(message);
        em
    }

    #[test]
    fn eme_pkcs1_v15_unpad_recovers_the_message() {
        let em = pkcs1_v15_pad(b"hello world", 256);
        assert_eq!(eme_pkcs1_v15_unpad(&em).unwrap(), b"hello world");
    }

    #[test]
    fn eme_pkcs1_v15_unpad_rejects_bad_first_bytes() {
        let mut em = pkcs1_v15_pad(b"hello world", 256);
        em[1] = 0x01;
        assert_eq!(eme_pkcs1_v15_unpad(&em), Err(CKR_ENCRYPTED_DATA_INVALID.into()));
    }

    #[test]
    fn eme_pkcs1_v15_unpad_rejects_missing_separator() {
        let em = vec![0x00, 0x02].into_iter().chain(std::iter::repeat(0xFFu8).take(254)).collect::<Vec<u8>>();
        assert_eq!(eme_pkcs1_v15_unpad(&em), Err(CKR_ENCRYPTED_DATA_INVALID.into()));
    }

    #[test]
    fn eme_oaep_round_trips_with_hand_written_reference_encode() {
        // A from-scratch EME-OAEP-ENCODE (RFC 8017 §7.1.1), written
        // independently of `eme_oaep_unpad` itself, so the round trip
        // actually exercises two separate implementations of the same math
        // rather than just checking a function undoes its own bug.
        fn oaep_encode(message: &[u8], label: &[u8], modulus_len: usize, h_len: usize) -> Vec<u8> {
            let mut l_hasher = DigestOp::new(CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            l_hasher.update(label);
            let l_hash = l_hasher.finalize();
            let ps_len = modulus_len - message.len() - 2 * h_len - 2;
            let mut db = l_hash.clone();
            db.extend(std::iter::repeat(0u8).take(ps_len));
            db.push(0x01);
            db.extend_from_slice(message);
            let seed = vec![0x42u8; h_len];
            let db_mask = mgf1(&seed, db.len(), CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
            let seed_mask = mgf1(&masked_db, h_len, CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();
            let mut em = vec![0x00u8];
            em.extend(masked_seed);
            em.extend(masked_db);
            em
        }

        let modulus_len = 256;
        let h_len = 32; // SHA-256
        let message = b"the quick brown fox";
        let em = oaep_encode(message, b"", modulus_len, h_len);
        assert_eq!(em.len(), modulus_len);

        let recovered = eme_oaep_unpad(
            &em,
            b"",
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn eme_oaep_unpad_rejects_tampered_block() {
        fn oaep_encode(message: &[u8], label: &[u8], modulus_len: usize, h_len: usize) -> Vec<u8> {
            let mut l_hasher = DigestOp::new(CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            l_hasher.update(label);
            let l_hash = l_hasher.finalize();
            let ps_len = modulus_len - message.len() - 2 * h_len - 2;
            let mut db = l_hash.clone();
            db.extend(std::iter::repeat(0u8).take(ps_len));
            db.push(0x01);
            db.extend_from_slice(message);
            let seed = vec![0x42u8; h_len];
            let db_mask = mgf1(&seed, db.len(), CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
            let seed_mask = mgf1(&masked_db, h_len, CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
            let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();
            let mut em = vec![0x00u8];
            em.extend(masked_seed);
            em.extend(masked_db);
            em
        }

        let mut em = oaep_encode(b"the quick brown fox", b"", 256, 32);
        em[255] ^= 0x01;
        assert_eq!(
            eme_oaep_unpad(&em, b"", CKM_SHA256 as CK_MECHANISM_TYPE, CKM_SHA256 as CK_MECHANISM_TYPE),
            Err(CKR_ENCRYPTED_DATA_INVALID.into())
        );
    }

}
