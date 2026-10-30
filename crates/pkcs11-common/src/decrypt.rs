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

use crate::digest::DigestOp;
use crate::sign::mgf1;
use pkcs11_sys::*;

pub fn eme_pkcs1_v15_unpad(em: &[u8]) -> Result<Vec<u8>, CK_RV> {
    // EM = 0x00 || 0x02 || PS || 0x00 || M, with PS at
    // least 8 bytes of non-zero padding => a valid EM is at least 11
    // bytes, the first two bytes are fixed.
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
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let db_mask = mgf1(&seed, masked_db.len(), mgf_hash_mechanism)?;
    let db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

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
        assert_eq!(
            eme_pkcs1_v15_unpad(&em),
            Err(CKR_ENCRYPTED_DATA_INVALID.into())
        );
    }

    #[test]
    fn eme_pkcs1_v15_unpad_rejects_missing_separator() {
        let em = vec![0x00, 0x02]
            .into_iter()
            .chain(std::iter::repeat(0xFFu8).take(254))
            .collect::<Vec<u8>>();
        assert_eq!(
            eme_pkcs1_v15_unpad(&em),
            Err(CKR_ENCRYPTED_DATA_INVALID.into())
        );
    }

    #[test]
    fn eme_oaep_round_trips_with_hand_written_reference_encode() {
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
            let masked_seed: Vec<u8> = seed
                .iter()
                .zip(seed_mask.iter())
                .map(|(a, b)| a ^ b)
                .collect();
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
            let masked_seed: Vec<u8> = seed
                .iter()
                .zip(seed_mask.iter())
                .map(|(a, b)| a ^ b)
                .collect();
            let mut em = vec![0x00u8];
            em.extend(masked_seed);
            em.extend(masked_db);
            em
        }

        let mut em = oaep_encode(b"the quick brown fox", b"", 256, 32);
        em[255] ^= 0x01;
        assert_eq!(
            eme_oaep_unpad(
                &em,
                b"",
                CKM_SHA256 as CK_MECHANISM_TYPE,
                CKM_SHA256 as CK_MECHANISM_TYPE
            ),
            Err(CKR_ENCRYPTED_DATA_INVALID.into())
        );
    }
}
