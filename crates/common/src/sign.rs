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
use pkcs11_sys::*;

/// The DER prefix of a PKCS#1 `DigestInfo` for each
/// hash algorithm
pub fn digest_info_prefix(hash_mechanism: CK_MECHANISM_TYPE) -> Option<&'static [u8]> {
    match hash_mechanism as u32 {
        CKM_SHA_1 => Some(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]),
        CKM_SHA256 => Some(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        CKM_SHA384 => Some(&[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]),
        CKM_SHA512 => Some(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        _ => None,
    }
}

pub fn pkcs1_v15_pad(digest_info: &[u8], modulus_len: usize) -> Result<Vec<u8>, CK_RV> {
    // Need room for 0x00 0x01, at least 8 bytes of 0xFF padding (RFC 8017's
    // minimum), and the 0x00 separator, on top of digest_info itself.
    if digest_info.len() + 11 > modulus_len {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let ps_len = modulus_len - digest_info.len() - 3;
    let mut out = Vec::with_capacity(modulus_len);
    out.push(0x00);
    out.push(0x01);
    out.extend(std::iter::repeat(0xFFu8).take(ps_len));
    out.push(0x00);
    out.extend_from_slice(digest_info);
    Ok(out)
}

pub fn zero_pad(data: &[u8], modulus_len: usize) -> Result<Vec<u8>, CK_RV> {
    if data.len() > modulus_len {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut out = vec![0u8; modulus_len];
    out[modulus_len - data.len()..].copy_from_slice(data);
    Ok(out)
}

/// MGF1 mask generation function (RFC 8017 Appendix B.2.1): repeatedly
/// hashes `seed || counter` (a 4-byte big-endian counter starting at 0),
/// concatenating the results, and truncates to `mask_len` bytes.
pub fn mgf1(
    seed: &[u8],
    mask_len: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let mut out = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while out.len() < mask_len {
        let mut hasher = DigestOp::new(hash_mechanism)?;
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(mask_len);
    Ok(out)
}

pub fn emsa_pss_encode(
    m_hash: &[u8],
    salt: &[u8],
    em_bits: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let h_len = m_hash.len();
    let em_len = em_bits.div_ceil(8);
    // RFC 8017 step 4: emLen < hLen + sLen + 2 is an encoding error.
    if em_len < h_len + salt.len() + 2 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }

    // Step 5-6: M' = 00 00 00 00 00 00 00 00 || mHash || salt; H = Hash(M').
    let mut m_prime = Vec::with_capacity(8 + h_len + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let mut h_hasher = DigestOp::new(hash_mechanism)?;
    h_hasher.update(&m_prime);
    let h = h_hasher.finalize();

    // Step 7-9: DB = PS || 0x01 || salt (PS is all-zero padding), masked
    // with MGF1(H).
    let ps_len = em_len - salt.len() - h_len - 2;
    let mut db = Vec::with_capacity(ps_len + 1 + salt.len());
    db.extend(std::iter::repeat(0u8).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(salt);

    let db_mask = mgf1(&h, db.len(), mgf_hash_mechanism)?;
    let mut masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // Step 10-11: zero the leftmost `8 * emLen - emBits` bits of the first
    // byte. emBits (the modulus's actual bit length minus one) isn't
    // always a multiple of 8, so emLen*8 can overshoot it by a few bits.
    let extra_bits = em_len * 8 - em_bits;
    if extra_bits > 0 {
        masked_db[0] &= 0xFFu8 >> extra_bits;
    }

    // Step 12: EM = maskedDB || H || 0xBC.
    let mut em = masked_db;
    em.extend_from_slice(&h);
    em.push(0xBC);
    Ok(em)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_prefix_lengths_match_rfc_8017_appendix_b1() {
        assert_eq!(
            digest_info_prefix(CKM_SHA_1 as CK_MECHANISM_TYPE)
                .unwrap()
                .len()
                + 20,
            35
        );
        assert_eq!(
            digest_info_prefix(CKM_SHA256 as CK_MECHANISM_TYPE)
                .unwrap()
                .len()
                + 32,
            51
        );
        assert_eq!(
            digest_info_prefix(CKM_SHA384 as CK_MECHANISM_TYPE)
                .unwrap()
                .len()
                + 48,
            67
        );
        assert_eq!(
            digest_info_prefix(CKM_SHA512 as CK_MECHANISM_TYPE)
                .unwrap()
                .len()
                + 64,
            83
        );
    }

    #[test]
    fn pkcs1_v15_pad_matches_rfc_8017_section_9_2_shape() {
        let digest_info = vec![0xAAu8; 35]; // stand-in SHA-1 DigestInfo
        let padded = pkcs1_v15_pad(&digest_info, 256).unwrap(); // 2048-bit modulus
        assert_eq!(padded.len(), 256);
        assert_eq!(padded[0], 0x00);
        assert_eq!(padded[1], 0x01);
        assert!(padded[2..256 - 35 - 1].iter().all(|&b| b == 0xFF));
        assert_eq!(padded[256 - 35 - 1], 0x00);
        assert_eq!(&padded[256 - 35..], digest_info.as_slice());
    }

    #[test]
    fn pkcs1_v15_pad_rejects_digest_info_too_large_for_modulus() {
        let digest_info = vec![0xAAu8; 250];
        assert!(pkcs1_v15_pad(&digest_info, 256).is_err());
    }

    #[test]
    fn zero_pad_left_pads_short_input() {
        let padded = zero_pad(&[0xAB, 0xCD], 4).unwrap();
        assert_eq!(padded, vec![0x00, 0x00, 0xAB, 0xCD]);
    }

    #[test]
    fn zero_pad_passes_through_exact_length_input() {
        let padded = zero_pad(&[0xAB, 0xCD, 0xEF, 0x01], 4).unwrap();
        assert_eq!(padded, vec![0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn zero_pad_rejects_input_longer_than_modulus() {
        assert!(zero_pad(&[0xAB, 0xCD, 0xEF], 2).is_err());
    }

    // Both vectors below were independently computed with a from-scratch
    // Python reference (stdlib `hashlib` only, no PKCS#11/RSA library),
    // cross-checking this implementation against RFC 8017 rather than
    // against itself.

    #[test]
    fn mgf1_matches_independently_computed_reference_vector() {
        let mask = mgf1(b"test-seed-value", 50, CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
        assert_eq!(
            hex(&mask),
            "3edf736ea62f3f0b5300055fed083d6d47cb2f249f66a326be7f69258b315c72171c7347b9dafbca3ad58a11103269730a4e"
        );
    }

    #[test]
    fn emsa_pss_encode_matches_independently_computed_reference_vector() {
        // mHash = SHA-256("abc"); salt = 0x00..0x13 (20 bytes, fixed rather
        // than random so the expected EM is reproducible); emBits = 528
        // (a 528-bit modulus, i.e. emLen = 66 bytes — picked only to be
        // comfortably larger than hLen + sLen + 2 = 54).
        let m_hash = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let salt: Vec<u8> = (0u8..20).collect();
        let em = emsa_pss_encode(
            &m_hash,
            &salt,
            528,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        assert_eq!(em.len(), 66);
        assert_eq!(
            hex(&em),
            "d715ac380173b51de1c1ad079eab6aec7545d3bbca6ac886a4b1e4230da0546bee23724dac4c52b25c3de763053a368824415afee922efd7247f31a376dffe5f47bc"
        );
    }

    #[test]
    fn emsa_pss_encode_rejects_salt_too_long_for_modulus() {
        let m_hash = [0u8; 32];
        let salt = vec![0u8; 64];
        assert!(
            emsa_pss_encode(
                &m_hash,
                &salt,
                528,
                CKM_SHA256 as CK_MECHANISM_TYPE,
                CKM_SHA256 as CK_MECHANISM_TYPE,
            )
            .is_err()
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
