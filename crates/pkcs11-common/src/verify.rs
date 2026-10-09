// Copyright 2026 Yubico AB

//! RSA/ECDSA/EdDSA signature verification — pure host-side math over raw
//! public-key bytes (RSA modulus/exponent, EC SEC1 point, Ed25519 raw key),
//! not any backend's own key-material type. A verify operation never needs
//! the device at all (only the public key, which every backend already
//! exposes for `CKA_MODULUS`/`CKA_EC_POINT`/etc attributes), so unlike
//! `sign.rs` this covers the *entire* operation, not just the host-side half
//! of it — matching both C references, which likewise do verification
//! entirely with a general-purpose crypto library (OpenSSL) rather than
//! asking the device, even when (as for yubihsm_pkcs11.c's RSA/EC/EdDSA
//! case) the public key itself has to be fetched from the device first.
//!
//! Deliberately generic over which backend calls it — see `ykcs11::verify`
//! for the orchestration layer (object lookup, mechanism classification,
//! session state) that's specific to PIV today; a future yubihsm-pkcs11
//! verify implementation should be able to reuse every function here
//! unchanged, just supplying its own raw key bytes.

use crate::digest::DigestOp;
use crate::sign::{digest_info_prefix, mgf1, pkcs1_v15_pad, zero_pad};
use pkcs11_sys::*;
use rsa::BigUint;

/// The raw RSA public-key operation (`s^e mod n`), zero-padded to
/// `modulus_len` bytes — the same operation RSA verification always starts
/// from, regardless of padding scheme (PKCS#1 v1.5, PSS, or none at all for
/// `CKM_RSA_X_509`). Uses `rsa::hazmat::rsa_encrypt` (the crate's deliberately
/// low-level, no-padding primitive — verification needs exactly that raw
/// operation, not any of the crate's own higher-level signature schemes,
/// which this project can't use anyway since this project's modulus/exponent
/// come from a device's public key, not an `rsa::RsaPublicKey` constructed
/// from a private key).
fn rsa_public_raw_op(
    n: &[u8],
    e: &[u8],
    signature: &[u8],
    modulus_len: usize,
) -> Result<Vec<u8>, CK_RV> {
    if signature.len() != modulus_len {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let pub_key = rsa::RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let m = BigUint::from_bytes_be(signature);
    let result = rsa::hazmat::rsa_encrypt(&pub_key, &m).map_err(|_| CK_RV::from(CKR_SIGNATURE_INVALID))?;
    zero_pad(&result.to_bytes_be(), modulus_len)
}

/// `CKM_RSA_X_509` verify: the raw RSA public-key operation's output, once
/// zero-padded to `modulus_len`, must equal `message` zero-padded the same
/// way — matches both C references doing a plain `EVP_PKEY_verify` with
/// `RSA_NO_PADDING` (ykcs11's mechanisms.c:380-426, yubihsm's
/// util_pkcs11.c:3407-3509), i.e. OpenSSL does the same raw-operation-then-
/// compare this does explicitly.
pub fn verify_rsa_x509(
    n: &[u8],
    e: &[u8],
    modulus_len: usize,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CK_RV> {
    let expected = zero_pad(message, modulus_len)?;
    let actual = rsa_public_raw_op(n, e, signature, modulus_len)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

/// `CKM_RSA_PKCS`/`CKM_SHAx_RSA_PKCS` verify (RFC 8017 §9.2): recompute the
/// expected padded block (`DigestInfo`-wrapped only when `hash_mechanism` is
/// `Some` — matches `sign.rs`'s identical asymmetry on the signing side) via
/// the same `pkcs1_v15_pad`/`digest_info_prefix` this project already uses
/// to *produce* PKCS#1 v1.5 signatures, and compare it byte-for-byte against
/// the raw RSA public-key operation's output.
pub fn verify_rsa_pkcs1v15(
    n: &[u8],
    e: &[u8],
    modulus_len: usize,
    hash_mechanism: Option<CK_MECHANISM_TYPE>,
    message_or_hash: &[u8],
    signature: &[u8],
) -> Result<(), CK_RV> {
    let to_pad = match hash_mechanism {
        Some(h) => {
            let prefix = digest_info_prefix(h).ok_or(CK_RV::from(CKR_MECHANISM_INVALID))?;
            let mut v = Vec::with_capacity(prefix.len() + message_or_hash.len());
            v.extend_from_slice(prefix);
            v.extend_from_slice(message_or_hash);
            v
        }
        None => message_or_hash.to_vec(),
    };
    let expected = pkcs1_v15_pad(&to_pad, modulus_len)?;
    let actual = rsa_public_raw_op(n, e, signature, modulus_len)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) — the inverse of `sign.rs`'s
/// `emsa_pss_encode`: given the encoded message `em` (the raw RSA public-key
/// operation's output), recover the mask, re-derive the salt, recompute
/// `H'`, and compare it to the `H` embedded in `em`.
fn emsa_pss_verify(
    m_hash: &[u8],
    em: &[u8],
    em_bits: usize,
    salt_len: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
) -> Result<(), CK_RV> {
    let h_len = m_hash.len();
    let em_len = em_bits.div_ceil(8);
    // Steps 3-4: too short to hold hLen + sLen + 2, or missing the 0xBC
    // trailer, is "inconsistent" (i.e. just an invalid signature, not a
    // distinct error).
    if em.len() != em_len || em_len < h_len + salt_len + 2 {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    if em[em_len - 1] != 0xBC {
        return Err(CKR_SIGNATURE_INVALID.into());
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..em_len - 1];

    // Step 6: the leftmost `8*emLen - emBits` bits of maskedDB's first byte
    // must already be zero (mirrors `emsa_pss_encode`'s own step 10-11,
    // which clears exactly those bits before masking).
    let extra_bits = em_len * 8 - em_bits;
    if extra_bits > 0 && (masked_db[0] & !(0xFFu8 >> extra_bits)) != 0 {
        return Err(CKR_SIGNATURE_INVALID.into());
    }

    let db_mask = mgf1(h, db_len, mgf_hash_mechanism)?;
    let mut db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    if extra_bits > 0 {
        db[0] &= 0xFFu8 >> extra_bits;
    }

    // Step 10: leftmost `emLen - hLen - sLen - 2` octets of DB must be zero,
    // followed by a single 0x01 byte, then the salt.
    let ps_len = db_len - salt_len - 1;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return Err(CKR_SIGNATURE_INVALID.into());
    }
    let salt = &db[ps_len + 1..];

    // Steps 12-13: M' = 00*8 || mHash || salt; H' = Hash(M').
    let mut m_prime = Vec::with_capacity(8 + h_len + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let mut h_hasher = DigestOp::new(hash_mechanism)?;
    h_hasher.update(&m_prime);
    let h_prime = h_hasher.finalize();

    if h_prime == h {
        Ok(())
    } else {
        Err(CKR_SIGNATURE_INVALID.into())
    }
}

/// `CKM_RSA_PKCS_PSS`/`CKM_SHAx_RSA_PKCS_PSS` verify: raw RSA public-key
/// operation, then `emsa_pss_verify`.
#[allow(clippy::too_many_arguments)]
pub fn verify_rsa_pss(
    n: &[u8],
    e: &[u8],
    modulus_len: usize,
    modulus_bits: usize,
    hash_mechanism: CK_MECHANISM_TYPE,
    mgf_hash_mechanism: CK_MECHANISM_TYPE,
    salt_len: usize,
    message_or_hash: &[u8],
    signature: &[u8],
) -> Result<(), CK_RV> {
    let em = rsa_public_raw_op(n, e, signature, modulus_len)?;
    emsa_pss_verify(
        message_or_hash,
        &em,
        modulus_bits - 1,
        salt_len,
        hash_mechanism,
        mgf_hash_mechanism,
    )
}

/// `CKM_ECDSA`/`CKM_ECDSA_SHAx` verify. `point` is the key's raw SEC1 point
/// bytes (the same bytes `CKA_EC_POINT` wraps); `signature` is PKCS#11's
/// fixed-width `r || s`. No manual truncation of `prehash` to the curve's
/// field width is needed here (unlike the signing side, where
/// `yubikit::piv::sign()` is a dumb passthrough) — `ecdsa::Signature`'s own
/// `verify_prehash` already reduces an over/under-length digest via
/// `bits2field` (SEC1 §2.3.8's `bits2int`), which left-truncates/left-pads
/// exactly like the PIV hardware does when signing (both rules agree
/// byte-for-byte here since P-256/P-384's order is itself byte-aligned).
pub fn verify_ecdsa(
    curve_byte_len: usize,
    point: &[u8],
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), CK_RV> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    if signature.len() != curve_byte_len * 2 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }

    match curve_byte_len {
        32 => {
            let pk = p256::PublicKey::from_sec1_bytes(point)
                .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let vk: p256::ecdsa::VerifyingKey = pk.into();
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_LEN_RANGE))?;
            vk.verify_prehash(prehash, &sig)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_INVALID))
        }
        48 => {
            let pk = p384::PublicKey::from_sec1_bytes(point)
                .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let vk: p384::ecdsa::VerifyingKey = pk.into();
            let sig = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_LEN_RANGE))?;
            vk.verify_prehash(prehash, &sig)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_INVALID))
        }
        // Callers only ever resolve 32 (P-256) or 48 (P-384).
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

/// `CKM_EDDSA` verify. `key` is the raw 32-byte Ed25519 public key;
/// `signature` is the raw fixed 64-byte signature (no DER wrapping, matching
/// the signing side's identical "no post-processing" treatment).
pub fn verify_eddsa(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CK_RV> {
    use ed25519_dalek::Verifier;

    if signature.len() != 64 {
        return Err(CKR_SIGNATURE_LEN_RANGE.into());
    }
    let key_bytes: [u8; 32] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
    // SAFETY-free: length already checked above.
    let sig_bytes: [u8; 64] = signature.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).map_err(|_| CK_RV::from(CKR_SIGNATURE_INVALID))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::emsa_pss_encode;

    // 2048-bit RSA test key (n, e, d) -- not from any real device, generated
    // purely for these unit tests.
    include!("verify_test_key.rs");

    fn modexp(input: &[u8], exp: &[u8]) -> Vec<u8> {
        let base = BigUint::from_bytes_be(input);
        let e = BigUint::from_bytes_be(exp);
        let n = BigUint::from_bytes_be(TEST_RSA_N);
        base.modpow(&e, &n).to_bytes_be()
    }

    #[test]
    fn verify_rsa_pkcs1v15_accepts_a_genuine_signature() {
        let hash = [0x11u8; 32]; // stand-in SHA-256 digest
        let prefix = digest_info_prefix(CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
        let mut digest_info = prefix.to_vec();
        digest_info.extend_from_slice(&hash);
        let em = pkcs1_v15_pad(&digest_info, 256).unwrap();
        let sig = zero_pad(&modexp(&em, TEST_RSA_D), 256).unwrap();

        verify_rsa_pkcs1v15(
            TEST_RSA_N,
            TEST_RSA_E,
            256,
            Some(CKM_SHA256 as CK_MECHANISM_TYPE),
            &hash,
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn verify_rsa_pkcs1v15_rejects_a_tampered_signature() {
        let hash = [0x11u8; 32];
        let prefix = digest_info_prefix(CKM_SHA256 as CK_MECHANISM_TYPE).unwrap();
        let mut digest_info = prefix.to_vec();
        digest_info.extend_from_slice(&hash);
        let em = pkcs1_v15_pad(&digest_info, 256).unwrap();
        let mut sig = zero_pad(&modexp(&em, TEST_RSA_D), 256).unwrap();
        sig[255] ^= 0x01;

        assert_eq!(
            verify_rsa_pkcs1v15(
                TEST_RSA_N,
                TEST_RSA_E,
                256,
                Some(CKM_SHA256 as CK_MECHANISM_TYPE),
                &hash,
                &sig,
            ),
            Err(CKR_SIGNATURE_INVALID.into())
        );
    }

    #[test]
    fn verify_rsa_pkcs1v15_rejects_wrong_length_signature() {
        let hash = [0x11u8; 32];
        assert_eq!(
            verify_rsa_pkcs1v15(
                TEST_RSA_N,
                TEST_RSA_E,
                256,
                Some(CKM_SHA256 as CK_MECHANISM_TYPE),
                &hash,
                &[0u8; 255],
            ),
            Err(CKR_SIGNATURE_LEN_RANGE.into())
        );
    }

    #[test]
    fn verify_rsa_x509_accepts_a_genuine_signature() {
        let message = [0x22u8; 256];
        let sig = zero_pad(&modexp(&message, TEST_RSA_D), 256).unwrap();
        verify_rsa_x509(TEST_RSA_N, TEST_RSA_E, 256, &message, &sig).unwrap();
    }

    #[test]
    fn verify_rsa_pss_round_trips_with_emsa_pss_encode() {
        let m_hash = [0x33u8; 32];
        let salt = [0x44u8; 32];
        let em = emsa_pss_encode(
            &m_hash,
            &salt,
            2047,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        let sig = zero_pad(&modexp(&em, TEST_RSA_D), 256).unwrap();

        verify_rsa_pss(
            TEST_RSA_N,
            TEST_RSA_E,
            256,
            2048,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            32,
            &m_hash,
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn verify_rsa_pss_rejects_a_tampered_signature() {
        let m_hash = [0x33u8; 32];
        let salt = [0x44u8; 32];
        let em = emsa_pss_encode(
            &m_hash,
            &salt,
            2047,
            CKM_SHA256 as CK_MECHANISM_TYPE,
            CKM_SHA256 as CK_MECHANISM_TYPE,
        )
        .unwrap();
        let mut sig = zero_pad(&modexp(&em, TEST_RSA_D), 256).unwrap();
        sig[255] ^= 0x01;

        assert_eq!(
            verify_rsa_pss(
                TEST_RSA_N,
                TEST_RSA_E,
                256,
                2048,
                CKM_SHA256 as CK_MECHANISM_TYPE,
                CKM_SHA256 as CK_MECHANISM_TYPE,
                32,
                &m_hash,
                &sig,
            ),
            Err(CKR_SIGNATURE_INVALID.into())
        );
    }

    #[test]
    fn verify_ecdsa_p256_accepts_a_genuine_signature() {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[0x7Au8; 32].into()).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let point = vk.to_encoded_point(false);
        let prehash = [0x55u8; 32];

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&prehash).unwrap();

        verify_ecdsa(32, point.as_bytes(), &prehash, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_ecdsa_p256_rejects_a_tampered_signature() {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[0x7Au8; 32].into()).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let point = vk.to_encoded_point(false);
        let prehash = [0x55u8; 32];

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&prehash).unwrap();
        let mut raw = sig.to_bytes();
        raw[0] ^= 0x01;

        assert_eq!(
            verify_ecdsa(32, point.as_bytes(), &prehash, &raw),
            Err(CKR_SIGNATURE_INVALID.into())
        );
    }

    #[test]
    fn verify_ecdsa_rejects_wrong_length_signature() {
        assert_eq!(
            verify_ecdsa(32, &[0u8; 65], &[0u8; 32], &[0u8; 63]),
            Err(CKR_SIGNATURE_LEN_RANGE.into())
        );
    }

    #[test]
    fn verify_eddsa_accepts_a_genuine_signature() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x66u8; 32]);
        let vk = sk.verifying_key();
        let message = b"test message";

        use ed25519_dalek::Signer;
        let sig = sk.sign(message);

        verify_eddsa(vk.as_bytes(), message, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_eddsa_rejects_a_tampered_signature() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x66u8; 32]);
        let vk = sk.verifying_key();
        let message = b"test message";

        use ed25519_dalek::Signer;
        let sig = sk.sign(message);
        let mut raw = sig.to_bytes();
        raw[0] ^= 0x01;

        assert_eq!(
            verify_eddsa(vk.as_bytes(), message, &raw),
            Err(CKR_SIGNATURE_INVALID.into())
        );
    }
}
