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

use crate::backend::{PivBackend, piv_error_to_rv};
use crate::objects::refresh_slot_objects;
use crate::template::{
    P256_CURVE_OID, P384_CURVE_OID, find_attr, is_public_exponent_65537, require_so_login,
};
use der::Decode;
use pkcs11_common::backend::Slot;
use pkcs11_common::yk_dbg;
use pkcs11_sys::*;
use yubikit::keys::{
    EcCurve, EcPrivateKey, Ed25519PrivateKey, MlDsaParameterSet, MlDsaPrivateKey,
    MlKemParameterSet, MlKemPrivateKey, PrivateKey, RsaKeySize, RsaPrivateKey, X25519PrivateKey,
};

fn map_key_error(_: yubikit::keys::KeyError) -> CK_RV {
    CKR_ATTRIBUTE_VALUE_INVALID.into()
}

/// Read `CKA_SEED` if present, else `CKA_VALUE`. A caller that only supplies the
/// full expanded key (no `CKA_SEED`) still gets its bytes sent to the
/// device, which is the actual authority on what it'll accept, rather than
/// this module rejecting the template client-side.
fn resolve_pqc_key_bytes<'a>(
    template: &'a [(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    key_type_label: &str,
) -> Result<&'a [u8], CK_RV> {
    if let Some(seed) = find_attr(template, CKA_SEED) {
        return Ok(seed);
    }
    if let Some(value) = find_attr(template, CKA_VALUE) {
        yk_dbg!(
            "resolve_private_key: {} template has no CKA_SEED, falling back to CKA_VALUE (the device will reject this if it isn't the seed)",
            key_type_label
        );
        return Ok(value);
    }
    yk_dbg!(
        "resolve_private_key: {} template missing both CKA_SEED and CKA_VALUE",
        key_type_label
    );
    Err(CKR_TEMPLATE_INCOMPLETE.into())
}

fn rsa_key_size_from_prime_len(len: usize) -> Option<RsaKeySize> {
    Some(match len {
        63 | 64 => RsaKeySize::Rsa1024,
        127 | 128 => RsaKeySize::Rsa2048,
        191 | 192 => RsaKeySize::Rsa3072,
        255 | 256 => RsaKeySize::Rsa4096,
        _ => return None,
    })
}

/// Parses private parameters for import
fn resolve_private_key(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Result<PrivateKey, CK_RV> {
    let key_type = find_attr(template, CKA_KEY_TYPE).ok_or_else(|| {
        yk_dbg!("resolve_private_key: missing CKA_KEY_TYPE");
        CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
    })?;
    let key_type = CK_ULONG::from_ne_bytes(
        key_type
            .try_into()
            .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
    );

    match key_type as u32 {
        CKK_RSA => {
            let e = find_attr(template, CKA_PUBLIC_EXPONENT)
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let p = find_attr(template, CKA_PRIME_1).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let q = find_attr(template, CKA_PRIME_2).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dp =
                find_attr(template, CKA_EXPONENT_1).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dq =
                find_attr(template, CKA_EXPONENT_2).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let qinv =
                find_attr(template, CKA_COEFFICIENT).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;

            if !is_public_exponent_65537(e) {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            }

            let key_size = rsa_key_size_from_prime_len(p.len())
                .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

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
            let params =
                find_attr(template, CKA_EC_PARAMS).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let curve = if params == P256_CURVE_OID {
                EcCurve::P256
            } else if params == P384_CURVE_OID {
                EcCurve::P384
            } else {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            };
            let scalar =
                find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let ec = EcPrivateKey::new(curve, scalar.to_vec(), None).map_err(map_key_error)?;
            Ok(PrivateKey::Ec(ec))
        }
        CKK_EC_EDWARDS => {
            let secret =
                find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = Ed25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::Ed25519(key))
        }
        CKK_EC_MONTGOMERY => {
            let secret =
                find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = X25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::X25519(key))
        }
        CKK_ML_DSA => {
            let param_bytes = find_attr(template, CKA_PARAMETER_SET).ok_or_else(|| {
                yk_dbg!("resolve_private_key: CKK_ML_DSA template missing CKA_PARAMETER_SET");
                CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
            })?;
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
            let seed = resolve_pqc_key_bytes(template, "CKK_ML_DSA")?;
            let key = MlDsaPrivateKey::new(parameter_set, seed.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::MlDsa(key))
        }
        CKK_ML_KEM => {
            let param_bytes = find_attr(template, CKA_PARAMETER_SET).ok_or_else(|| {
                yk_dbg!("resolve_private_key: CKK_ML_KEM template missing CKA_PARAMETER_SET");
                CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
            })?;
            let param_set = CK_ULONG::from_ne_bytes(
                param_bytes
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            let parameter_set = match param_set as u32 {
                CKP_ML_KEM_512 => MlKemParameterSet::MlKem512,
                CKP_ML_KEM_768 => MlKemParameterSet::MlKem768,
                CKP_ML_KEM_1024 => MlKemParameterSet::MlKem1024,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            };
            let seed = resolve_pqc_key_bytes(template, "CKK_ML_KEM")?;
            let key = MlKemPrivateKey::new(parameter_set, seed.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::MlKem(key))
        }
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
    }
}

pub fn create_object(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    require_so_login(slot.login_state)?;

    yk_dbg!(
        "create_object: template attribute types = [{}]",
        template
            .iter()
            .map(|(t, v)| format!("{:#06x}({}B)", t, v.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let class = find_attr(template, CKA_CLASS).ok_or_else(|| {
        yk_dbg!("create_object: missing CKA_CLASS");
        CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
    })?;
    let class = CK_ULONG::from_ne_bytes(
        class
            .try_into()
            .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
    );

    let id = find_attr(template, CKA_ID)
        .and_then(|b| b.first().copied())
        .ok_or_else(|| {
            yk_dbg!("create_object: missing or empty CKA_ID");
            CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
        })?;
    let piv_slot =
        crate::objects::slot_from_cka_id(id).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

    match class as u32 {
        CKO_CERTIFICATE => {
            let value =
                find_attr(template, CKA_VALUE).ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;

            // Verifies that the bytes are a valid X.509 structure before import.
            x509_cert::Certificate::from_der(value)
                .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;

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
        assert!(matches!(
            resolve_private_key(&p256_t),
            Ok(PrivateKey::Ec(_))
        ));

        let p384_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG),
            attr(CKA_EC_PARAMS, P384_CURVE_OID),
            attr(CKA_VALUE, &[0x01u8; 48]),
        ];
        assert!(matches!(
            resolve_private_key(&p384_t),
            Ok(PrivateKey::Ec(_))
        ));
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
        assert!(matches!(
            resolve_private_key(&ed_t),
            Ok(PrivateKey::Ed25519(_))
        ));

        let x_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC_MONTGOMERY as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert!(matches!(
            resolve_private_key(&x_t),
            Ok(PrivateKey::X25519(_))
        ));
    }

    #[test]
    fn resolve_pqc_key_bytes_prefers_seed_over_value() {
        let t = [attr(CKA_SEED, &[0xAAu8; 4]), attr(CKA_VALUE, &[0xBBu8; 8])];
        assert_eq!(resolve_pqc_key_bytes(&t, "test").unwrap(), &[0xAAu8; 4][..]);
    }

    #[test]
    fn resolve_pqc_key_bytes_falls_back_to_value_when_seed_is_absent() {
        let t = [attr(CKA_VALUE, &[0xBBu8; 8])];
        assert_eq!(resolve_pqc_key_bytes(&t, "test").unwrap(), &[0xBBu8; 8][..]);
    }

    #[test]
    fn resolve_pqc_key_bytes_rejects_missing_both_seed_and_value() {
        let t: [(CK_ATTRIBUTE_TYPE, Vec<u8>); 0] = [];
        assert_eq!(
            resolve_pqc_key_bytes(&t, "test"),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
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
                    assert_eq!(
                        k.algorithm(),
                        yubikit::keys::KeyAlgorithm::MlDsa(expected_param_set)
                    )
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
    fn resolve_private_key_falls_back_to_value_for_ml_dsa_when_seed_is_absent() {
        // The device is the actual authority on whether these bytes are
        // acceptable (it'll reject a non-seed payload itself) -- this
        // module doesn't pre-emptively fail the template just because
        // CKA_SEED specifically wasn't the attribute supplied.
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_44 as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 2560]),
        ];
        assert!(matches!(resolve_private_key(&t), Ok(PrivateKey::MlDsa(_))));
    }

    #[test]
    fn resolve_private_key_rejects_an_ml_dsa_template_missing_both_seed_and_value() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_DSA as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_DSA_44 as CK_ULONG),
        ];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }

    #[test]
    fn resolve_private_key_accepts_ml_kem_templates_for_every_parameter_set() {
        for (param_set, expected_param_set) in [
            (CKP_ML_KEM_512, MlKemParameterSet::MlKem512),
            (CKP_ML_KEM_768, MlKemParameterSet::MlKem768),
            (CKP_ML_KEM_1024, MlKemParameterSet::MlKem1024),
        ] {
            let t = [
                ulong_attr(CKA_KEY_TYPE, CKK_ML_KEM as CK_ULONG),
                ulong_attr(CKA_PARAMETER_SET, param_set as CK_ULONG),
                attr(CKA_SEED, &[0x01u8; 64]),
            ];
            match resolve_private_key(&t) {
                Ok(PrivateKey::MlKem(ref k)) => {
                    assert_eq!(
                        k.algorithm(),
                        yubikit::keys::KeyAlgorithm::MlKem(expected_param_set)
                    )
                }
                other => panic!("expected Ok(PrivateKey::MlKem(_)), got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_private_key_rejects_an_unrecognized_ml_kem_parameter_set() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_KEM as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, 0xFFFF),
            attr(CKA_SEED, &[0x01u8; 64]),
        ];
        assert_resolve_err(&t, CKR_ATTRIBUTE_VALUE_INVALID.into());
    }

    #[test]
    fn resolve_private_key_rejects_an_ml_kem_template_missing_parameter_set() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_KEM as CK_ULONG),
            attr(CKA_SEED, &[0x01u8; 64]),
        ];
        assert_resolve_err(&t, CKR_TEMPLATE_INCOMPLETE.into());
    }

    #[test]
    fn resolve_private_key_falls_back_to_value_for_ml_kem_when_seed_is_absent() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_KEM as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_KEM_512 as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 1632]),
        ];
        assert!(matches!(resolve_private_key(&t), Ok(PrivateKey::MlKem(_))));
    }

    #[test]
    fn resolve_private_key_rejects_an_ml_kem_template_missing_both_seed_and_value() {
        let t = [
            ulong_attr(CKA_KEY_TYPE, CKK_ML_KEM as CK_ULONG),
            ulong_attr(CKA_PARAMETER_SET, CKP_ML_KEM_512 as CK_ULONG),
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
