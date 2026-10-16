// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_GenerateKeyPair` backend logic for the YubiKey PIV module. Scope
//! matches ykcs11.c's own `generation_mechanisms[]` (mechanisms.c:41-47)
//! plus one deliberate addition: `CKM_RSA_PKCS_KEY_PAIR_GEN`,
//! `CKM_EC_KEY_PAIR_GEN`, `CKM_EC_EDWARDS_KEY_PAIR_GEN`,
//! `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` — RSA 1024/2048/3072/4096, EC
//! P-256/P-384, Ed25519, X25519 — and `CKM_ML_DSA_KEY_PAIR_GEN` covering all
//! three ML-DSA parameter sets (`CKA_PARAMETER_SET` = `CKP_ML_DSA_44`/`_65`/
//! `_87`, selecting `yubikit::piv::KeyType::MlDsa44`/`MlDsa65`/`MlDsa87`
//! respectively). `yubikit::piv`'s `generate_key` already supports ML-KEM
//! too, but the C reference has no concept of it (no `CKK_ML_KEM` mechanism
//! exists anywhere in it), so that stays out of scope here, same disclosed
//! gap as `objects.rs`'s own doc comment.
//!
//! Unlike `C_Sign*`/`C_Verify*`/`C_Encrypt*`/`C_Decrypt*`, this is a single
//! atomic call with no `Init`/`Update`/`Final` split and no per-session
//! operation state — PKCS#11 doesn't define `C_GenerateKeyPair` as
//! conflicting with an in-progress sign/verify/encrypt/decrypt operation
//! the way ykcs11.c's single shared `op_info` union incidentally does
//! (ykcs11.c:3523-3527, `session->op_info.type != YKCS11_NOOP` →
//! `CKR_OPERATION_ACTIVE`); this port deliberately doesn't replicate that
//! union-sharing artifact, consistent with already treating
//! sign/verify/encrypt/decrypt as independent concurrent operation types.
//!
//! Device-side, this does three things in sequence: generates the key pair
//! itself (`yubikit::piv::PivSession::generate_key`, the Rust equivalent of
//! the raw `INS_GENERATE_ASYMMETRIC` APDU `token_generate_key` builds by
//! hand in the C reference, token.c:378-505); builds and writes a
//! disposable self-signed placeholder X.509 certificate for the slot (the
//! device only ever returns raw key material, never a certificate — the C
//! reference manufactures one itself purely so the slot isn't cert-less,
//! `do_create_empty_cert`, openssl_utils.c:190-242); and refreshes the
//! slot's cached objects in place (`objects::refresh_slot_objects`) rather
//! than re-running discovery for all 25 slots.

use crate::backend::{PivBackend, piv_error_to_rv};
use crate::objects::refresh_slot_objects;
use crate::template::{
    P256_CURVE_OID, P384_CURVE_OID, find_attr, find_byte, is_public_exponent_65537, require_so_login,
    resolve_policies,
};
use der::{Decode, Encode};
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use yubikit::piv::{KeyType, Slot as PivSlot};

enum KeyFamily {
    Rsa,
    Ec,
    Ed25519,
    X25519,
    MlDsa,
}

fn classify_generate_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<KeyFamily> {
    Some(match mechanism as u32 {
        CKM_RSA_PKCS_KEY_PAIR_GEN => KeyFamily::Rsa,
        CKM_EC_KEY_PAIR_GEN => KeyFamily::Ec,
        CKM_EC_EDWARDS_KEY_PAIR_GEN => KeyFamily::Ed25519,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN => KeyFamily::X25519,
        CKM_ML_DSA_KEY_PAIR_GEN => KeyFamily::MlDsa,
        _ => return None,
    })
}

/// `CKA_ID`, required in at least one template — present in both, they must
/// agree (matches objects.c:2990-2996's cross-check).
fn resolve_slot(
    public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<PivSlot, CK_RV> {
    let pub_id = find_byte(public_key_template, CKA_ID)?;
    let priv_id = find_byte(private_key_template, CKA_ID)?;
    let id = match (pub_id, priv_id) {
        (Some(a), Some(b)) if a == b => a,
        (Some(_), Some(_)) => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => return Err(CKR_TEMPLATE_INCOMPLETE.into()),
    };
    crate::objects::slot_from_cka_id(id).ok_or(CKR_ATTRIBUTE_VALUE_INVALID.into())
}

/// `CKA_KEY_TYPE`, if present in either template, must agree with the
/// mechanism's own key family (objects.c's per-mechanism template checkers
/// all validate this) — matches `CKR_TEMPLATE_INCONSISTENT` on mismatch.
fn check_key_type_consistency(
    family: &KeyFamily,
    public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(), CK_RV> {
    let expected = match family {
        KeyFamily::Rsa => CKK_RSA,
        KeyFamily::Ec => CKK_EC,
        KeyFamily::Ed25519 => CKK_EC_EDWARDS,
        KeyFamily::X25519 => CKK_EC_MONTGOMERY,
        KeyFamily::MlDsa => CKK_ML_DSA,
    };
    for template in [public_key_template, private_key_template] {
        if let Some(bytes) = find_attr(template, CKA_KEY_TYPE) {
            let got = CK_ULONG::from_ne_bytes(
                bytes
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            if got != expected as CK_ULONG {
                return Err(CKR_TEMPLATE_INCONSISTENT.into());
            }
        }
    }
    Ok(())
}

/// `CKA_MODULUS_BITS` (RSA), `CKA_EC_PARAMS` (EC/Ed25519/X25519), or
/// `CKA_PARAMETER_SET` (ML-DSA) → `KeyType`. Matches
/// `check_rsa_pubkey_template`/`check_ec_pubkey_template`/
/// `check_ed_pubkey_template`/`check_x_pubkey_template` (objects.c:2638-
/// 2923): RSA size and EC curve are required; Ed25519/X25519 default purely
/// from the mechanism, with `CKA_EC_PARAMS` only checked if the caller
/// bothered to supply it. ML-DSA has no C reference to match — required
/// here since `CKM_ML_DSA_KEY_PAIR_GEN` alone doesn't disambiguate 44/65/87;
/// `CKP_ML_DSA_44`/`_65`/`_87` select the corresponding `KeyType` variant.
fn resolve_key_type(
    family: KeyFamily,
    public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<KeyType, CK_RV> {
    match family {
        KeyFamily::Rsa => {
            let bits = find_attr(public_key_template, CKA_MODULUS_BITS)
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let bits = CK_ULONG::from_ne_bytes(
                bits.try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            if let Some(e) = find_attr(public_key_template, CKA_PUBLIC_EXPONENT) {
                if !is_public_exponent_65537(e) {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(match bits {
                1024 => KeyType::Rsa1024,
                2048 => KeyType::Rsa2048,
                3072 => KeyType::Rsa3072,
                4096 => KeyType::Rsa4096,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            })
        }
        KeyFamily::Ec => {
            let params = find_attr(public_key_template, CKA_EC_PARAMS)
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            if params == P256_CURVE_OID {
                Ok(KeyType::EccP256)
            } else if params == P384_CURVE_OID {
                Ok(KeyType::EccP384)
            } else {
                Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
            }
        }
        KeyFamily::Ed25519 => {
            if let Some(params) = find_attr(public_key_template, CKA_EC_PARAMS) {
                if params != crate::objects::ED25519_CURVE_PARAMS {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(KeyType::Ed25519)
        }
        KeyFamily::X25519 => {
            if let Some(params) = find_attr(public_key_template, CKA_EC_PARAMS) {
                if params != crate::objects::X25519_CURVE_PARAMS {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(KeyType::X25519)
        }
        KeyFamily::MlDsa => {
            let bytes = find_attr(public_key_template, CKA_PARAMETER_SET)
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameter_set = CK_ULONG::from_ne_bytes(
                bytes
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            match parameter_set as u32 {
                CKP_ML_DSA_44 => Ok(KeyType::MlDsa44),
                CKP_ML_DSA_65 => Ok(KeyType::MlDsa65),
                CKP_ML_DSA_87 => Ok(KeyType::MlDsa87),
                _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            }
        }
    }
}

fn random_p256_signing_key() -> Result<p256::ecdsa::SigningKey, CK_RV> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
        if let Ok(key) = p256::ecdsa::SigningKey::from_bytes((&bytes).into()) {
            return Ok(key);
        }
    }
}

/// Builds a disposable self-signed placeholder certificate for `piv_slot`'s
/// freshly-generated public key — matches `do_create_empty_cert`
/// (openssl_utils.c:190-242): a throwaway P-256 signing key, CN "YubiKey PIV
/// Slot %x" (the real on-device slot byte, e.g. `9a`), self-signed, 10-year
/// validity (the C reference doesn't document a specific validity window
/// either — this is cosmetic, meant to be overwritten by a real CA-issued
/// cert later).
fn build_placeholder_cert(
    piv_slot: PivSlot,
    public_key: &yubikit::keys::PublicKey,
) -> Result<Vec<u8>, CK_RV> {
    build_placeholder_cert_with_signer(piv_slot, public_key, &random_p256_signing_key()?)
}

/// The actual cert-building logic, taking the throwaway signing key as a
/// parameter rather than drawing its own randomness — split out purely so
/// tests can supply a known key and verify the resulting signature, not
/// just the DER shape.
fn build_placeholder_cert_with_signer(
    piv_slot: PivSlot,
    public_key: &yubikit::keys::PublicKey,
    signing_key: &p256::ecdsa::SigningKey,
) -> Result<Vec<u8>, CK_RV> {
    let spki_der = public_key
        .to_spki()
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;

    let subject: Name = format!("CN=YubiKey PIV Slot {:x}", piv_slot as u8)
        .parse()
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    // Purely cosmetic -- this placeholder is self-signed and meant to be
    // overwritten by a real CA-issued cert, so the serial doesn't need to
    // be unique against anything. Matches both the C reference and
    // yubikit's own self-signed-cert test, which use the same fixed value.
    let serial = SerialNumber::new(&[0x01]).map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let validity = Validity::from_now(core::time::Duration::new(10 * 365 * 24 * 3600, 0))
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;

    let builder =
        CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, signing_key)
            .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    cert.to_der().map_err(|_| CKR_GENERAL_ERROR.into())
}

pub fn generate_key_pair(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
    // Matches C_GenerateKeyPair's own login check (ykcs11.c:3587-3592):
    // requires SO (PIV management key) authentication, not just a verified
    // PIN — generating a new key is a card-management operation.
    require_so_login(slot.login_state)?;

    let Some(family) = classify_generate_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    let piv_slot = resolve_slot(public_key_template, private_key_template)?;
    check_key_type_consistency(&family, public_key_template, private_key_template)?;
    let key_type = resolve_key_type(family, public_key_template)?;
    let (pin_policy, touch_policy) = resolve_policies(private_key_template)?;

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    let public_key = piv
        .generate_key(piv_slot, key_type, pin_policy, touch_policy)
        .map_err(piv_error_to_rv)?;

    let cert_der = build_placeholder_cert(piv_slot, &public_key)?;
    piv.put_certificate(piv_slot, &cert_der, false)
        .map_err(piv_error_to_rv)?;

    refresh_slot_objects(&mut slot.data.objects, piv, piv_slot);

    let pub_handle = crate::objects::PivObjectId::from_slot_class(
        crate::objects::ObjectClass::PublicKey,
        piv_slot,
    ) as CK_OBJECT_HANDLE;
    let priv_handle = crate::objects::PivObjectId::from_slot_class(
        crate::objects::ObjectClass::PrivateKey,
        piv_slot,
    ) as CK_OBJECT_HANDLE;

    Ok((pub_handle, priv_handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::CKA_YUBICO_PIN_POLICY;
    use yubikit::keys::{EcCurve, EcPublicKey, PublicKey};
    use yubikit::piv::{PinPolicy, TouchPolicy};

    fn attr(ty: u32, value: &[u8]) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_vec())
    }
    fn ulong_attr(ty: u32, value: CK_ULONG) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_ne_bytes().to_vec())
    }

    #[test]
    fn classify_generate_mechanism_matches_c_references_set() {
        assert!(matches!(
            classify_generate_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Rsa)
        ));
        assert!(matches!(
            classify_generate_mechanism(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Ec)
        ));
        assert!(matches!(
            classify_generate_mechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Ed25519)
        ));
        assert!(matches!(
            classify_generate_mechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::X25519)
        ));
        assert!(matches!(
            classify_generate_mechanism(CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::MlDsa)
        ));
        assert!(classify_generate_mechanism(CKM_AES_CBC as CK_MECHANISM_TYPE).is_none());
    }

    #[test]
    fn resolve_slot_requires_at_least_one_cka_id() {
        assert_eq!(resolve_slot(&[], &[]), Err(CKR_TEMPLATE_INCOMPLETE.into()));
    }

    #[test]
    fn resolve_slot_rejects_disagreement() {
        let pub_t = [attr(CKA_ID, &[1])];
        let priv_t = [attr(CKA_ID, &[2])];
        assert_eq!(
            resolve_slot(&pub_t, &priv_t),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn resolve_slot_accepts_agreement_and_maps_to_the_right_slot() {
        let pub_t = [attr(CKA_ID, &[3])];
        let priv_t = [attr(CKA_ID, &[3])];
        assert_eq!(resolve_slot(&pub_t, &priv_t), Ok(PivSlot::KeyManagement));
    }

    #[test]
    fn resolve_slot_rejects_attestation_and_out_of_range_ids() {
        assert_eq!(
            resolve_slot(&[attr(CKA_ID, &[25])], &[]),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
        assert_eq!(
            resolve_slot(&[attr(CKA_ID, &[30])], &[]),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn check_key_type_consistency_detects_mismatch() {
        let priv_t = [ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG)];
        assert_eq!(
            check_key_type_consistency(&KeyFamily::Rsa, &[], &priv_t),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn check_key_type_consistency_accepts_matching_type() {
        let priv_t = [ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG)];
        assert_eq!(
            check_key_type_consistency(&KeyFamily::Rsa, &[], &priv_t),
            Ok(())
        );
    }

    #[test]
    fn resolve_key_type_rsa_bit_sizes() {
        for (bits, expected) in [
            (1024, KeyType::Rsa1024),
            (2048, KeyType::Rsa2048),
            (3072, KeyType::Rsa3072),
            (4096, KeyType::Rsa4096),
        ] {
            let pub_t = [ulong_attr(CKA_MODULUS_BITS, bits)];
            assert_eq!(resolve_key_type(KeyFamily::Rsa, &pub_t), Ok(expected));
        }
    }

    #[test]
    fn resolve_key_type_rejects_unsupported_rsa_bit_size() {
        let pub_t = [ulong_attr(CKA_MODULUS_BITS, 1536)];
        assert_eq!(
            resolve_key_type(KeyFamily::Rsa, &pub_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn resolve_key_type_rejects_bad_public_exponent() {
        let pub_t = [
            ulong_attr(CKA_MODULUS_BITS, 2048),
            attr(CKA_PUBLIC_EXPONENT, &[0x03]),
        ];
        assert_eq!(
            resolve_key_type(KeyFamily::Rsa, &pub_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn resolve_key_type_accepts_correct_public_exponent() {
        let pub_t = [
            ulong_attr(CKA_MODULUS_BITS, 2048),
            attr(CKA_PUBLIC_EXPONENT, &[0x01, 0x00, 0x01]),
        ];
        assert_eq!(
            resolve_key_type(KeyFamily::Rsa, &pub_t),
            Ok(KeyType::Rsa2048)
        );
    }

    #[test]
    fn resolve_key_type_ec_curve_oid_matching() {
        let p256_t = [attr(CKA_EC_PARAMS, P256_CURVE_OID)];
        assert_eq!(
            resolve_key_type(KeyFamily::Ec, &p256_t),
            Ok(KeyType::EccP256)
        );
        let p384_t = [attr(CKA_EC_PARAMS, P384_CURVE_OID)];
        assert_eq!(
            resolve_key_type(KeyFamily::Ec, &p384_t),
            Ok(KeyType::EccP384)
        );
        let bad_t = [attr(CKA_EC_PARAMS, &[0x06, 0x01, 0x00])];
        assert_eq!(
            resolve_key_type(KeyFamily::Ec, &bad_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn resolve_key_type_ed25519_defaults_from_mechanism_alone() {
        assert_eq!(
            resolve_key_type(KeyFamily::Ed25519, &[]),
            Ok(KeyType::Ed25519)
        );
        assert_eq!(
            resolve_key_type(KeyFamily::X25519, &[]),
            Ok(KeyType::X25519)
        );
    }

    #[test]
    fn resolve_key_type_ml_dsa_parameter_sets() {
        for (param_set, expected) in [
            (CKP_ML_DSA_44, KeyType::MlDsa44),
            (CKP_ML_DSA_65, KeyType::MlDsa65),
            (CKP_ML_DSA_87, KeyType::MlDsa87),
        ] {
            let pub_t = [ulong_attr(CKA_PARAMETER_SET, param_set as CK_ULONG)];
            assert_eq!(resolve_key_type(KeyFamily::MlDsa, &pub_t), Ok(expected));
        }
    }

    #[test]
    fn resolve_key_type_ml_dsa_rejects_unknown_parameter_set() {
        let bad_t = [ulong_attr(CKA_PARAMETER_SET, 0xFFFF)];
        assert_eq!(
            resolve_key_type(KeyFamily::MlDsa, &bad_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn resolve_key_type_ml_dsa_requires_parameter_set() {
        assert_eq!(
            resolve_key_type(KeyFamily::MlDsa, &[]),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn resolve_policies_defaults_to_token_default() {
        assert_eq!(
            resolve_policies(&[]),
            Ok((PinPolicy::Default, TouchPolicy::Default))
        );
    }

    #[test]
    fn resolve_policies_always_authenticate_forces_pin_always() {
        let priv_t = [attr(CKA_ALWAYS_AUTHENTICATE, &[1])];
        assert_eq!(
            resolve_policies(&priv_t),
            Ok((PinPolicy::Always, TouchPolicy::Default))
        );
    }

    #[test]
    fn resolve_policies_always_authenticate_conflicts_with_explicit_non_always_pin() {
        let priv_t = [
            attr(CKA_YUBICO_PIN_POLICY as u32, &[PinPolicy::Once as u8]),
            attr(CKA_ALWAYS_AUTHENTICATE, &[1]),
        ];
        assert_eq!(
            resolve_policies(&priv_t),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn build_placeholder_cert_produces_a_verifiable_self_signed_cert() {
        use p256::ecdsa::signature::Verifier;

        // The "device" key embedded as the cert's subject — deliberately a
        // *different* key than the one that signs the cert, matching the
        // C reference's own placeholder-cert semantics (the throwaway
        // signer never corresponds to the subject's own key).
        let device_sk = p256::ecdsa::SigningKey::from_bytes((&[0x11u8; 32]).into()).unwrap();
        let device_vk = p256::ecdsa::VerifyingKey::from(&device_sk);
        let point = device_vk.to_encoded_point(false).as_bytes().to_vec();
        let public_key = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P256,
            point,
        });

        let signer = p256::ecdsa::SigningKey::from_bytes((&[0x22u8; 32]).into()).unwrap();
        let signer_vk = p256::ecdsa::VerifyingKey::from(&signer);

        let cert_der =
            build_placeholder_cert_with_signer(PivSlot::Authentication, &public_key, &signer)
                .unwrap();
        assert!(cert_der.len() > 100);

        let parsed = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");
        assert_eq!(
            parsed.tbs_certificate.subject.to_string(),
            "CN=YubiKey PIV Slot 9a"
        );

        // The embedded subject key must be the *device's* key, not the signer's.
        assert_eq!(
            parsed
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            public_key.to_spki().unwrap()
        );

        // The signature must verify against the throwaway signer's key.
        let tbs_der = parsed.tbs_certificate.to_der().expect("encode TBS");
        let cert_sig = p256::ecdsa::DerSignature::from_der(parsed.signature.raw_bytes())
            .expect("parse signature");
        signer_vk
            .verify(&tbs_der, &cert_sig)
            .expect("signature verifies");
    }
}
