// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_CreateObject` backend logic for the YubiKey PIV module. Scope matches
//! ykcs11.c's own `C_CreateObject` (ykcs11.c:1417-1676) exactly: only
//! `CKO_CERTIFICATE` (import a DER certificate) and `CKO_PRIVATE_KEY`
//! (import an externally-supplied private key onto the device) are
//! supported — `CKO_DATA`/`CKO_PUBLIC_KEY`/`CKO_SECRET_KEY` have no case in
//! the C reference either, and aren't supported here.
//!
//! Same SO (PIV management key) login requirement as `C_GenerateKeyPair`
//! (ykcs11.c:1499-1504/1604-1609) — importing objects is a card-management
//! operation. Device-side: certificate import reuses the exact same
//! `piv.put_certificate()` call `generate::generate_key_pair` already uses
//! for its placeholder cert; private-key import uses
//! `yubikit::piv::PivSession::put_key`, the Rust equivalent of
//! `ykpiv_import_private_key`. Both paths refresh the slot's cached objects
//! via `objects::refresh_slot_objects` afterward, same as generate.
//!
//! One behavioral difference from the C reference worth flagging: ykcs11.c
//! never cross-checks an imported certificate's public key against any
//! private key material already in that slot (`store_cert`'s
//! `force_pubkey = CK_TRUE` just unconditionally overwrites the cached
//! public key) — this port does the same, trusting the caller.

use crate::backend::{PivBackend, piv_error_to_rv};
use crate::objects::refresh_slot_objects;
use crate::template::{P256_CURVE_OID, P384_CURVE_OID, find_attr, is_public_exponent_65537, require_so_login};
use der::Decode;
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;
use yubikit::keys::{
    EcCurve, EcPrivateKey, Ed25519PrivateKey, MlDsaParameterSet, MlDsaPrivateKey, PrivateKey,
    RsaKeySize, RsaPrivateKey, X25519PrivateKey,
};

fn map_key_error(_: yubikit::keys::KeyError) -> CK_RV {
    CKR_ATTRIBUTE_VALUE_INVALID.into()
}

/// `p`'s byte length (the RSA CRT prime, half the modulus) → `RsaKeySize` —
/// matches ykcs11.c's own inference (ykcs11.c:1555-1582): `p_len` 63/64 →
/// 1024, 127/128 → 2048, 191/192 → 3072, 255/256 → 4096 (the C reference
/// accepts either the exact half-modulus byte count or one byte short, for
/// a prime whose DER/transport encoding dropped a leading zero).
fn rsa_key_size_from_prime_len(len: usize) -> Option<RsaKeySize> {
    Some(match len {
        63 | 64 => RsaKeySize::Rsa1024,
        127 | 128 => RsaKeySize::Rsa2048,
        191 | 192 => RsaKeySize::Rsa3072,
        255 | 256 => RsaKeySize::Rsa4096,
        _ => return None,
    })
}

/// `CKO_PRIVATE_KEY` import: `CKA_KEY_TYPE` selects which attribute set to
/// read, matching `check_create_rsa_key`/`check_create_ec_key`/
/// `check_create_ed_key`/`check_create_x25519_key` (objects.c:2155-2467+).
/// RSA uses the CRT components (`CKA_PRIME_1/2`, `CKA_EXPONENT_1/2`,
/// `CKA_COEFFICIENT`) — *not* `CKA_MODULUS`/`CKA_PRIVATE_EXPONENT`, which
/// the C reference's template checker never reads either. EC/Ed25519/
/// X25519 use the raw private scalar (`CKA_VALUE`), with EC's curve chosen
/// via `CKA_EC_PARAMS` the same way `generate::resolve_key_type` does.
/// ML-DSA has no C reference to match — it uses `CKA_SEED` (PKCS#11 3.2's
/// dedicated "new post-quantum (general)" attribute, pkcs11t.h:675), *not*
/// `CKA_VALUE`: the device's import APDU only ever accepts the 32-byte
/// FIPS 204 seed, never the full expanded private key, so `CKA_VALUE` (if
/// present at all, e.g. carrying the full key for the caller's own records)
/// is simply never read here. The parameter set is chosen via
/// `CKA_PARAMETER_SET`, the same way `generate::resolve_key_type` does for
/// `CKM_ML_DSA_KEY_PAIR_GEN`.
fn resolve_private_key(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Result<PrivateKey, CK_RV> {
    let key_type = find_attr(template, CKA_KEY_TYPE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
    let key_type = CK_ULONG::from_ne_bytes(
        key_type
            .try_into()
            .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
    );

    match key_type as u32 {
        CKK_RSA => {
            let e = find_attr(template, CKA_PUBLIC_EXPONENT).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let p = find_attr(template, CKA_PRIME_1).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let q = find_attr(template, CKA_PRIME_2).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dp = find_attr(template, CKA_EXPONENT_1).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dq = find_attr(template, CKA_EXPONENT_2).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let qinv = find_attr(template, CKA_COEFFICIENT).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;

            if !is_public_exponent_65537(e) {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }

            let key_size = rsa_key_size_from_prime_len(p.len()).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

            let rsa = RsaPrivateKey::new(
                key_size,
                Vec::new(), // CKA_MODULUS isn't part of this template either, matching ykcs11.c.
                e.to_vec(),
                p.to_vec(),
                q.to_vec(),
                dp.to_vec(),
                dq.to_vec(),
                qinv.to_vec(),
            )
            .map_err(map_key_error)?;
            Ok(PrivateKey::Rsa(rsa))
        }
        CKK_EC => {
            let params = find_attr(template, CKA_EC_PARAMS).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let curve = if params == P256_CURVE_OID {
                EcCurve::P256
            } else if params == P384_CURVE_OID {
                EcCurve::P384
            } else {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            };
            let scalar = find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let ec = EcPrivateKey::new(curve, scalar.to_vec(), None).map_err(map_key_error)?;
            Ok(PrivateKey::Ec(ec))
        }
        CKK_EC_EDWARDS => {
            let secret = find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = Ed25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::Ed25519(key))
        }
        CKK_EC_MONTGOMERY => {
            let secret = find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = X25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::X25519(key))
        }
        CKK_ML_DSA => {
            let param_bytes = find_attr(template, CKA_PARAMETER_SET)
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let param_set = CK_ULONG::from_ne_bytes(
                param_bytes
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            let parameter_set = match param_set as u32 {
                CKP_ML_DSA_44 => MlDsaParameterSet::MlDsa44,
                CKP_ML_DSA_65 => MlDsaParameterSet::MlDsa65,
                CKP_ML_DSA_87 => MlDsaParameterSet::MlDsa87,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            };
            let seed = find_attr(template, CKA_SEED).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = MlDsaPrivateKey::new(parameter_set, seed.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::MlDsa(key))
        }
        // No ML-KEM here — unlike ML-DSA above and
        // `generate::generate_key_pair` (which generates ML-KEM 512/768/1024
        // on-device), importing externally generated ML-KEM key material is
        // still out of scope.
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

pub fn create_object(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    require_so_login(slot.login_state)?;

    let class = find_attr(template, CKA_CLASS).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
    let class = CK_ULONG::from_ne_bytes(
        class
            .try_into()
            .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
    );

    let id = find_attr(template, CKA_ID)
        .and_then(|b| b.first().copied())
        .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
    let piv_slot =
        crate::objects::slot_from_cka_id(id).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

    match class as u32 {
        CKO_CERTIFICATE => {
            let value = find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            // Matches do_check_cert (openssl_utils.c:244) — just confirms
            // the bytes parse as a valid X.509 structure before writing
            // them to the device; no cross-check against any existing key.
            x509_cert::Certificate::from_der(value).map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

            let piv = slot
                .data
                .piv_session
                .as_mut()
                .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
            piv.put_certificate(piv_slot, value, false)
                .map_err(piv_error_to_rv)?;
            refresh_slot_objects(&mut slot.data.objects, piv, piv_slot);

            Ok(crate::objects::PivObjectId::from_slot_class(
                crate::objects::ObjectClass::Certificate,
                piv_slot,
            ) as CK_OBJECT_HANDLE)
        }
        CKO_PRIVATE_KEY => {
            let private_key = resolve_private_key(template)?;
            let (pin_policy, touch_policy) = crate::template::resolve_policies(template)?;

            let piv = slot
                .data
                .piv_session
                .as_mut()
                .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
            piv.put_key(piv_slot, &private_key, pin_policy, touch_policy)
                .map_err(piv_error_to_rv)?;
            refresh_slot_objects(&mut slot.data.objects, piv, piv_slot);

            Ok(crate::objects::PivObjectId::from_slot_class(
                crate::objects::ObjectClass::PrivateKey,
                piv_slot,
            ) as CK_OBJECT_HANDLE)
        }
        // CKO_DATA/CKO_PUBLIC_KEY/CKO_SECRET_KEY have no case in ykcs11.c's
        // own C_CreateObject either.
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u32, value: &[u8]) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_vec())
    }
    fn ulong_attr(ty: u32, value: CK_ULONG) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_ne_bytes().to_vec())
    }

    // `PrivateKey` (the `Ok` side of `resolve_private_key`) isn't `Debug`, so
    // `assert_eq!`/`unwrap_err` can't be used directly on the whole `Result`.
    fn assert_resolve_err(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)], want: CK_RV) {
        match resolve_private_key(template) {
            Err(got) => assert_eq!(got, want),
            Ok(_) => panic!("expected {want:?}, got Ok"),
        }
    }

    #[test]
    fn rsa_key_size_from_prime_len_matches_c_reference_table() {
        assert_eq!(rsa_key_size_from_prime_len(63), Some(RsaKeySize::Rsa1024));
        assert_eq!(rsa_key_size_from_prime_len(64), Some(RsaKeySize::Rsa1024));
        assert_eq!(rsa_key_size_from_prime_len(127), Some(RsaKeySize::Rsa2048));
        assert_eq!(rsa_key_size_from_prime_len(128), Some(RsaKeySize::Rsa2048));
        assert_eq!(rsa_key_size_from_prime_len(191), Some(RsaKeySize::Rsa3072));
        assert_eq!(rsa_key_size_from_prime_len(192), Some(RsaKeySize::Rsa3072));
        assert_eq!(rsa_key_size_from_prime_len(255), Some(RsaKeySize::Rsa4096));
        assert_eq!(rsa_key_size_from_prime_len(256), Some(RsaKeySize::Rsa4096));
        assert_eq!(rsa_key_size_from_prime_len(65), None);
        assert_eq!(rsa_key_size_from_prime_len(0), None);
    }

    #[test]
    fn resolve_private_key_accepts_a_well_formed_rsa1024_template() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG),
            attr(CKA_PUBLIC_EXPONENT, &[0x01, 0x00, 0x01]),
            attr(CKA_PRIME_1, &[0xAAu8; 64]),
            attr(CKA_PRIME_2, &[0xBBu8; 64]),
            attr(CKA_EXPONENT_1, &[0xCCu8; 64]),
            attr(CKA_EXPONENT_2, &[0xDDu8; 64]),
            attr(CKA_COEFFICIENT, &[0xEEu8; 64]),
        ];
        assert!(matches!(resolve_private_key(&t), Ok(PrivateKey::Rsa(_))));
    }

    #[test]
    fn resolve_private_key_rejects_a_non_standard_rsa_public_exponent() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG),
            attr(CKA_PUBLIC_EXPONENT, &[0x03]),
            attr(CKA_PRIME_1, &[0xAAu8; 64]),
            attr(CKA_PRIME_2, &[0xBBu8; 64]),
            attr(CKA_EXPONENT_1, &[0xCCu8; 64]),
            attr(CKA_EXPONENT_2, &[0xDDu8; 64]),
            attr(CKA_COEFFICIENT, &[0xEEu8; 64]),
        ];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_unrecognized_rsa_key_size() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG),
            attr(CKA_PUBLIC_EXPONENT, &[0x01, 0x00, 0x01]),
            attr(CKA_PRIME_1, &[0xAAu8; 65]),
            attr(CKA_PRIME_2, &[0xBBu8; 65]),
            attr(CKA_EXPONENT_1, &[0xCCu8; 65]),
            attr(CKA_EXPONENT_2, &[0xDDu8; 65]),
            attr(CKA_COEFFICIENT, &[0xEEu8; 65]),
        ];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_incomplete_rsa_template() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG),
            attr(CKA_PUBLIC_EXPONENT, &[0x01, 0x00, 0x01]),
            attr(CKA_PRIME_1, &[0xAAu8; 64]),
            // CKA_PRIME_2 and the rest are missing.
        ];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }

    #[test]
    fn resolve_private_key_accepts_p256_and_p384_ec_templates() {
        let p256_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG),
            attr(CKA_EC_PARAMS, P256_CURVE_OID),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert!(matches!(resolve_private_key(&p256_t), Ok(PrivateKey::Ec(_))));

        let p384_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG),
            attr(CKA_EC_PARAMS, P384_CURVE_OID),
            attr(CKA_VALUE, &[0x01u8; 48]),
        ];
        assert!(matches!(resolve_private_key(&p384_t), Ok(PrivateKey::Ec(_))));
    }

    #[test]
    fn resolve_private_key_rejects_an_unrecognized_ec_curve() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG),
            attr(CKA_EC_PARAMS, &[0x06, 0x01, 0x00]),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_accepts_ed25519_and_x25519_templates() {
        let ed_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC_EDWARDS as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert!(matches!(resolve_private_key(&ed_t), Ok(PrivateKey::Ed25519(_))));

        let x_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC_MONTGOMERY as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert!(matches!(resolve_private_key(&x_t), Ok(PrivateKey::X25519(_))));
    }

    #[test]
    fn resolve_private_key_accepts_ml_dsa_templates_for_every_parameter_set() {
        for (param_set, expected_param_set) in [
            (CKP_ML_DSA_44, MlDsaParameterSet::MlDsa44),
            (CKP_ML_DSA_65, MlDsaParameterSet::MlDsa65),
            (CKP_ML_DSA_87, MlDsaParameterSet::MlDsa87),
        ] {
            let t = [
                ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
                ulong_attr(CKA_PARAMETER_SET, param_set as CK_ULONG),
                attr(CKA_SEED, &[0x01u8; 32]),
            ];
            match resolve_private_key(&t) {
                Ok(PrivateKey::MlDsa(ref k)) => {
                    assert_eq!(k.algorithm(), yubikit::keys::KeyAlgorithm::MlDsa(expected_param_set))
                }
                other => panic!("expected Ok(PrivateKey::MlDsa(_)), got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_private_key_rejects_an_unrecognized_ml_dsa_parameter_set() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, 0xFFFF),
            attr(CKA_SEED, &[0x01u8; 32]),
        ];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_ml_dsa_template_missing_parameter_set() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
            attr(CKA_SEED, &[0x01u8; 32]),
        ];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_ml_dsa_template_missing_seed() {
        // CKA_VALUE alone isn't enough -- only CKA_SEED is read, since the
        // device only ever accepts the 32-byte seed, never the full
        // expanded private key CKA_VALUE might otherwise carry.
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_44 as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 2560]),
        ];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_unsupported_key_type() {
        let t = [ulong_attr(CKA_KEY_TYPE, CKK_GENERIC_SECRET as CK_ULONG)];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_rejects_a_template_missing_key_type() {
        let t: [(CK_ATTRIBUTE_TYPE, Vec<u8>); 0] = [];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }
}
