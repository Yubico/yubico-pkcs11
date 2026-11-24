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
    P256_CURVE_OID, P384_CURVE_OID, is_public_exponent_65537, parse_policies, require_so_login,
};
use common::backend::Slot;
use common::yk_dbg;
use der::Decode;
use pkcs11_sys::*;
use yubikit::keys::{
    EcCurve, EcPrivateKey, Ed25519PrivateKey, MlDsaParameterSet, MlDsaPrivateKey,
    MlKemParameterSet, MlKemPrivateKey, PrivateKey, RsaKeySize, RsaPrivateKey, X25519PrivateKey,
};
use yubikit::piv::Slot as PivSlot;

fn map_key_error(_: yubikit::keys::KeyError) -> CK_RV {
    CKR_ATTRIBUTE_VALUE_INVALID.into()
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

/// Raw per-key-type attribute bytes, collected during the single template
/// scan `parse_template` does. Which fields are actually required depends
/// on `CKA_KEY_TYPE`, which isn't known until that same scan finds it --
/// so unlike `generate.rs`'s `KeyParams` (picked up front from the
/// mechanism), this stays a flat bag of `Option`s until `resolve_private_key`
/// validates it against the now-known key type.
#[derive(Default)]
struct RawKeyParams {
    public_exponent: Option<Vec<u8>>,
    prime_1: Option<Vec<u8>>,
    prime_2: Option<Vec<u8>>,
    exponent_1: Option<Vec<u8>>,
    exponent_2: Option<Vec<u8>>,
    coefficient: Option<Vec<u8>>,
    ec_params: Option<Vec<u8>>,
    /// `CKA_VALUE` -- shared by the certificate path, EC/Ed25519/X25519
    /// private keys, and as the ML-DSA/ML-KEM fallback when `CKA_SEED`
    /// isn't supplied.
    value: Option<Vec<u8>>,
    seed: Option<Vec<u8>>,
    parameter_set: Option<Vec<u8>>,
}

/// Every attribute `create_object` might need, extracted from the raw
/// template in one pass. Whether a given field is actually required
/// depends on `class` and (for a private key) `key_type` -- validated by
/// `resolve_private_key`/the certificate path afterward, not during this
/// parse.
#[derive(Default)]
struct CreateObjectTemplate {
    class: Option<CK_ULONG>,
    piv_slot: Option<PivSlot>,
    key_type: Option<CK_ULONG>,
    key_params: RawKeyParams,
    pin_policy_value: Option<u8>,
    touch_policy_value: Option<u8>,
    always_auth_value: Option<u8>,
}

fn parse_template(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<CreateObjectTemplate, CK_RV> {
    let mut t = CreateObjectTemplate::default();

    for (attr_type, value) in template {
        match *attr_type as u32 {
            CKA_CLASS => {
                t.class = Some(CK_ULONG::from_ne_bytes(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                ));
            }
            CKA_ID => {
                let id = *value
                    .first()
                    .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
                t.piv_slot = Some(
                    crate::piv_key_slot::slot_from_ckaid(id)
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            CKA_KEY_TYPE => {
                t.key_type = Some(CK_ULONG::from_ne_bytes(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                ));
            }
            CKA_PUBLIC_EXPONENT => t.key_params.public_exponent = Some(value.clone()),
            CKA_PRIME_1 => t.key_params.prime_1 = Some(value.clone()),
            CKA_PRIME_2 => t.key_params.prime_2 = Some(value.clone()),
            CKA_EXPONENT_1 => t.key_params.exponent_1 = Some(value.clone()),
            CKA_EXPONENT_2 => t.key_params.exponent_2 = Some(value.clone()),
            CKA_COEFFICIENT => t.key_params.coefficient = Some(value.clone()),
            CKA_EC_PARAMS => t.key_params.ec_params = Some(value.clone()),
            CKA_VALUE => t.key_params.value = Some(value.clone()),
            CKA_SEED => t.key_params.seed = Some(value.clone()),
            CKA_PARAMETER_SET => t.key_params.parameter_set = Some(value.clone()),
            crate::objects::CKA_YUBICO_PIN_POLICY => {
                t.pin_policy_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            crate::objects::CKA_YUBICO_TOUCH_POLICY => {
                t.touch_policy_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            CKA_ALWAYS_AUTHENTICATE => {
                t.always_auth_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            _ => {}
        }
    }

    Ok(t)
}

/// Returns `CKA_SEED` if present, else `CKA_VALUE`. A caller that only
/// supplies the full expanded key (no `CKA_SEED`) still gets its bytes sent
/// to the device, which is the actual authority on what it'll accept,
/// rather than this module rejecting the template client-side.
fn parse_pqc_key_bytes<'a>(
    params: &'a RawKeyParams,
    key_type_label: &str,
) -> Result<&'a [u8], CK_RV> {
    if let Some(seed) = &params.seed {
        return Ok(seed);
    }
    if let Some(value) = &params.value {
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

/// Validates `key_type` and its matching fields in `params`, building the
/// `PrivateKey` to import. Only called once both are known, from the
/// already-parsed `CreateObjectTemplate` -- no template re-scanning here.
fn parse_private_key(key_type: CK_ULONG, params: &RawKeyParams) -> Result<PrivateKey, CK_RV> {
    match key_type as u32 {
        CKK_RSA => {
            let e = params
                .public_exponent
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let p = params
                .prime_1
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let q = params
                .prime_2
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dp = params
                .exponent_1
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let dq = params
                .exponent_2
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let qinv = params
                .coefficient
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;

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
            let ec_params = params
                .ec_params
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let curve = if ec_params == P256_CURVE_OID {
                EcCurve::P256
            } else if ec_params == P384_CURVE_OID {
                EcCurve::P384
            } else {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
            };
            let scalar = params
                .value
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let ec = EcPrivateKey::new(curve, scalar.to_vec(), None).map_err(map_key_error)?;
            Ok(PrivateKey::Ec(ec))
        }
        CKK_EC_EDWARDS => {
            let secret = params
                .value
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = Ed25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::Ed25519(key))
        }
        CKK_EC_MONTGOMERY => {
            let secret = params
                .value
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let key = X25519PrivateKey::new(secret.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::X25519(key))
        }
        CKK_ML_DSA => {
            let param_bytes = params.parameter_set.as_deref().ok_or_else(|| {
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
            let seed = parse_pqc_key_bytes(params, "CKK_ML_DSA")?;
            let key = MlDsaPrivateKey::new(parameter_set, seed.to_vec()).map_err(map_key_error)?;
            Ok(PrivateKey::MlDsa(key))
        }
        CKK_ML_KEM => {
            let param_bytes = params.parameter_set.as_deref().ok_or_else(|| {
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
            let seed = parse_pqc_key_bytes(params, "CKK_ML_KEM")?;
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

    let parsed = parse_template(template)?;

    let class = parsed.class.ok_or_else(|| {
        yk_dbg!("create_object: missing CKA_CLASS");
        CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
    })?;
    let piv_slot = parsed.piv_slot.ok_or_else(|| {
        yk_dbg!("create_object: missing or empty CKA_ID");
        CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
    })?;

    match class as u32 {
        CKO_CERTIFICATE => {
            let value = parsed
                .key_params
                .value
                .as_deref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;

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

            Ok(crate::piv_key_slot::PivObjectId::from_slot_class(
                crate::piv_key_slot::PivObjectClass::Certificate,
                piv_slot,
            ) as CK_OBJECT_HANDLE)
        }
        CKO_PRIVATE_KEY => {
            let key_type = parsed.key_type.ok_or_else(|| {
                yk_dbg!("resolve_private_key: missing CKA_KEY_TYPE");
                CK_RV::from(CKR_TEMPLATE_INCOMPLETE)
            })?;
            let private_key = parse_private_key(key_type, &parsed.key_params)?;
            let (pin_policy, touch_policy) = parse_policies(
                parsed.pin_policy_value,
                parsed.touch_policy_value,
                parsed.always_auth_value,
            )?;

            let piv = slot
                .data
                .piv_session
                .as_mut()
                .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
            piv.put_key(piv_slot, &private_key, pin_policy, touch_policy)
                .map_err(piv_error_to_rv)?;
            refresh_slot_objects(&mut slot.data.objects, piv, piv_slot);

            Ok(crate::piv_key_slot::PivObjectId::from_slot_class(
                crate::piv_key_slot::PivObjectClass::PrivateKey,
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

    /// Test-only convenience mirroring the old `resolve_private_key(&template)`
    /// shape: parses the raw template, then resolves the key from it, so
    /// existing test bodies below stay focused on template contents rather
    /// than the two-step parse/resolve split.
    fn resolve_private_key_from_raw(
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<PrivateKey, CK_RV> {
        let parsed = parse_template(template)?;
        let key_type = parsed
            .key_type
            .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
        parse_private_key(key_type, &parsed.key_params)
    }

    fn raw_key_params(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> RawKeyParams {
        parse_template(template).unwrap().key_params
    }

    // `PrivateKey` (the `Ok` side of `resolve_private_key_from_raw`) isn't
    // `Debug`, so `assert_eq!`/`unwrap_err` can't be used directly on the
    // whole `Result`.
    fn assert_resolve_err(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)], want: CK_RV) {
        match resolve_private_key_from_raw(template) {
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
        assert!(matches!(
            resolve_private_key_from_raw(&t),
            Ok(PrivateKey::Rsa(_))
        ));
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
            resolve_private_key_from_raw(&p256_t),
            Ok(PrivateKey::Ec(_))
        ));

        let p384_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG),
            attr(CKA_EC_PARAMS, P384_CURVE_OID),
            attr(CKA_VALUE, &[0x01u8; 48]),
        ];
        assert!(matches!(
            resolve_private_key_from_raw(&p384_t),
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
            resolve_private_key_from_raw(&ed_t),
            Ok(PrivateKey::Ed25519(_))
        ));

        let x_t = [
            ulong_attr(CKA_KEY_TYPE, CKK_EC_MONTGOMERY as CK_ULONG),
            attr(CKA_VALUE, &[0x01u8; 32]),
        ];
        assert!(matches!(
            resolve_private_key_from_raw(&x_t),
            Ok(PrivateKey::X25519(_))
        ));
    }

    #[test]
    fn resolve_pqc_key_bytes_prefers_seed_over_value() {
        let t = [attr(CKA_SEED, &[0xAAu8; 4]), attr(CKA_VALUE, &[0xBBu8; 8])];
        assert_eq!(
            parse_pqc_key_bytes(&raw_key_params(&t), "test").unwrap(),
            &[0xAAu8; 4][..]
        );
    }

    #[test]
    fn resolve_pqc_key_bytes_falls_back_to_value_when_seed_is_absent() {
        let t = [attr(CKA_VALUE, &[0xBBu8; 8])];
        assert_eq!(
            parse_pqc_key_bytes(&raw_key_params(&t), "test").unwrap(),
            &[0xBBu8; 8][..]
        );
    }

    #[test]
    fn resolve_pqc_key_bytes_rejects_missing_both_seed_and_value() {
        let t: [(CK_ATTRIBUTE_TYPE, Vec<u8>); 0] = [];
        assert_eq!(
            parse_pqc_key_bytes(&raw_key_params(&t), "test"),
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
            match resolve_private_key_from_raw(&t) {
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
        assert!(matches!(
            resolve_private_key_from_raw(&t),
            Ok(PrivateKey::MlDsa(_))
        ));
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
            match resolve_private_key_from_raw(&t) {
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
        assert!(matches!(
            resolve_private_key_from_raw(&t),
            Ok(PrivateKey::MlKem(_))
        ));
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
