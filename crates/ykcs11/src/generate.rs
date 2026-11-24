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
use der::{Decode, Encode};
use pkcs11_sys::*;
use x509_cert::TbsCertificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::Validity;
use yubikit::piv::{KeyType as KeyAlgorithm, PinPolicy, Slot as PivSlot, TouchPolicy};

struct RootProfile(Name);

impl BuilderProfile for RootProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.0.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();
        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(tbs.subject(), &extensions)?);
        extensions.push(
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_extension(tbs.subject(), &extensions)?,
        );
        Ok(extensions)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFamily {
    Rsa,
    Ec,
    Ed25519,
    X25519,
    MlDsa,
    MlKem,
}

/// The key-family-specific attributes relevant to key generation. Which
/// variant is present is decided up front from the mechanism's `KeyFamily`
/// (see `parse_template`), not inferred from the attributes seen -- so a
/// `GenTemplate` can't end up with, say, `ec_params` populated for an RSA
/// mechanism the way the old flat-`Option`-per-family struct could.
enum KeyParams {
    Rsa {
        bits: Option<CK_ULONG>,
        exponent: Option<Vec<u8>>,
    },
    /// Shared by `Ec`, `Ed25519` and `X25519` -- all three read `CKA_EC_PARAMS`;
    /// which curve it resolves to is decided by `KeyFamily` in `get_key_algorithm`.
    Ec { params: Option<Vec<u8>> },
    /// Shared by `MlDsa` and `MlKem` -- both read `CKA_PARAMETER_SET`.
    Pqc { parameter_set: Option<Vec<u8>> },
}

struct KeyTemplate {
    piv_slot: Option<PivSlot>,
    key_type: Option<CK_ULONG>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
    key_params: KeyParams,
}

fn parse_generate_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<KeyFamily> {
    Some(match mechanism as u32 {
        CKM_RSA_PKCS_KEY_PAIR_GEN => KeyFamily::Rsa,
        CKM_EC_KEY_PAIR_GEN => KeyFamily::Ec,
        CKM_EC_EDWARDS_KEY_PAIR_GEN => KeyFamily::Ed25519,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN => KeyFamily::X25519,
        CKM_ML_DSA_KEY_PAIR_GEN => KeyFamily::MlDsa,
        CKM_ML_KEM_KEY_PAIR_GEN => KeyFamily::MlKem,
        _ => return None,
    })
}

/// `CKA_ID`, if present in both templates, they have to match
fn get_slot_id(
    public_key_template: &KeyTemplate,
    private_key_template: &KeyTemplate,
) -> Result<PivSlot, CK_RV> {
    match (public_key_template.piv_slot, private_key_template.piv_slot) {
        (Some(a), Some(b)) if a == b => Ok(a),
        (Some(_), Some(_)) => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        (Some(a), None) | (None, Some(a)) => Ok(a),
        (None, None) => Err(CKR_TEMPLATE_INCOMPLETE.into()),
    }
}

/// `CKA_KEY_TYPE`, if present in either template, must agree with the
/// mechanism's own key family
fn check_key_type_consistency(
    family: &KeyFamily,
    public_key_template: &KeyTemplate,
    private_key_template: &KeyTemplate,
) -> Result<(), CK_RV> {
    let kt = match (public_key_template.key_type, private_key_template.key_type) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    };

    if let Some(kt) = kt {
        let expected = match family {
            KeyFamily::Rsa => CKK_RSA,
            KeyFamily::Ec => CKK_EC,
            KeyFamily::Ed25519 => CKK_EC_EDWARDS,
            KeyFamily::X25519 => CKK_EC_MONTGOMERY,
            KeyFamily::MlDsa => CKK_ML_DSA,
            KeyFamily::MlKem => CKK_ML_KEM,
        } as CK_ULONG;
        if expected == kt {
            return Ok(());
        }
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    Ok(())
}

/// Validates key type
fn get_key_algorithm(
    family: &KeyFamily,
    key_template: &KeyTemplate,
) -> Result<KeyAlgorithm, CK_RV> {
    match (family, &key_template.key_params) {
        (KeyFamily::Rsa, KeyParams::Rsa { bits, exponent }) => {
            let bits = bits.ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            if let Some(e) = exponent {
                if !is_public_exponent_65537(e.as_slice()) {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(match bits {
                1024 => KeyAlgorithm::Rsa1024,
                2048 => KeyAlgorithm::Rsa2048,
                3072 => KeyAlgorithm::Rsa3072,
                4096 => KeyAlgorithm::Rsa4096,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            })
        }
        (KeyFamily::Ec, KeyParams::Ec { params }) => {
            let params = params
                .as_ref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            if params == P256_CURVE_OID {
                Ok(KeyAlgorithm::EccP256)
            } else if params == P384_CURVE_OID {
                Ok(KeyAlgorithm::EccP384)
            } else {
                Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
            }
        }
        (KeyFamily::Ed25519, KeyParams::Ec { params }) => {
            if let Some(p) = params {
                if p != crate::objects::ED25519_CURVE_PARAMS {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(KeyAlgorithm::Ed25519)
        }
        (KeyFamily::X25519, KeyParams::Ec { params }) => {
            if let Some(p) = params {
                if p != crate::objects::X25519_CURVE_PARAMS {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            Ok(KeyAlgorithm::X25519)
        }
        (KeyFamily::MlDsa, KeyParams::Pqc { parameter_set }) => {
            let p = parameter_set
                .as_ref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameter_set = CK_ULONG::from_ne_bytes(
                p.as_slice()
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            match parameter_set as u32 {
                CKP_ML_DSA_44 => Ok(KeyAlgorithm::MlDsa44),
                CKP_ML_DSA_65 => Ok(KeyAlgorithm::MlDsa65),
                CKP_ML_DSA_87 => Ok(KeyAlgorithm::MlDsa87),
                _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            }
        }
        (KeyFamily::MlKem, KeyParams::Pqc { parameter_set }) => {
            let p = parameter_set
                .as_ref()
                .ok_or(CK_RV::from(CKR_TEMPLATE_INCOMPLETE))?;
            let parameter_set = CK_ULONG::from_ne_bytes(
                p.as_slice()
                    .try_into()
                    .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            );
            match parameter_set as u32 {
                CKP_ML_KEM_512 => Ok(KeyAlgorithm::MlKem512),
                CKP_ML_KEM_768 => Ok(KeyAlgorithm::MlKem768),
                CKP_ML_KEM_1024 => Ok(KeyAlgorithm::MlKem1024),
                _ => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
            }
        }
        // `parse_template` always builds `key_params` to match the
        // `KeyFamily` it was given, so `family`/`key_params` disagreeing is
        // unreachable in practice -- the type system just can't prove it,
        // since the two are still tracked as separate values rather than
        // one sum type.
        _ => Err(CKR_GENERAL_ERROR.into()),
    }
}

fn parse_template(
    key_family: KeyFamily,
    key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<KeyTemplate, CK_RV> {
    let mut pin_policy_value: Option<u8> = None;
    let mut touch_policy_value: Option<u8> = None;
    let mut always_auth_value: Option<u8> = None;
    let mut template = KeyTemplate {
        piv_slot: None,
        key_type: None,
        pin_policy: None,
        touch_policy: None,
        key_params: match key_family {
            KeyFamily::Rsa => KeyParams::Rsa {
                bits: None,
                exponent: None,
            },
            KeyFamily::Ec | KeyFamily::Ed25519 | KeyFamily::X25519 => {
                KeyParams::Ec { params: None }
            }
            KeyFamily::MlDsa | KeyFamily::MlKem => KeyParams::Pqc {
                parameter_set: None,
            },
        },
    };

    for (attr_type, value) in key_template {
        match *attr_type as u32 {
            CKA_ID => {
                let id = *value
                    .first()
                    .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?;
                template.piv_slot = Some(
                    crate::piv_key_slot::slot_from_ckaid(id).ok_or(CKR_ATTRIBUTE_VALUE_INVALID)?,
                );
            }
            CKA_KEY_TYPE => {
                template.key_type = Some(CK_ULONG::from_ne_bytes(
                    value
                        .as_slice()
                        .try_into()
                        .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                ));
            }
            CKA_MODULUS_BITS => {
                if let KeyParams::Rsa { bits, .. } = &mut template.key_params {
                    *bits = Some(CK_ULONG::from_ne_bytes(
                        value
                            .as_slice()
                            .try_into()
                            .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                    ));
                }
            }
            CKA_PUBLIC_EXPONENT => {
                if let KeyParams::Rsa { exponent, .. } = &mut template.key_params {
                    *exponent = Some(value.clone());
                }
            }
            CKA_EC_PARAMS => {
                if let KeyParams::Ec { params } = &mut template.key_params {
                    *params = Some(value.clone());
                }
            }
            CKA_PARAMETER_SET => {
                if let KeyParams::Pqc { parameter_set } = &mut template.key_params {
                    *parameter_set = Some(value.clone());
                }
            }
            crate::objects::CKA_YUBICO_PIN_POLICY => {
                pin_policy_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            crate::objects::CKA_YUBICO_TOUCH_POLICY => {
                touch_policy_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            CKA_ALWAYS_AUTHENTICATE => {
                always_auth_value = Some(
                    *value
                        .first()
                        .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
                );
            }
            _ => {}
        }
    }

    let (pp, tp) = parse_policies(pin_policy_value, touch_policy_value, always_auth_value)?;
    template.pin_policy = Some(pp);
    template.touch_policy = Some(tp);

    Ok(template)
}

fn disposable_signing_key() -> Result<p256::ecdsa::SigningKey, CK_RV> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
        if let Ok(key) = p256::ecdsa::SigningKey::from_bytes((&bytes).into()) {
            return Ok(key);
        }
    }
}

/// Builds a disposable self-signed placeholder certificate for a newly
/// generated key. Should be overwritten by a real CA-issued cert later.
/// The embedded subject key is `public_key` (the device's actual key); the
/// certificate is signed by a freshly drawn, throwaway key that's discarded
/// immediately after, and never corresponds to the subject's own key.
fn build_placeholder_cert(
    piv_slot: PivSlot,
    public_key: &yubikit::keys::PublicKey,
) -> Result<Vec<u8>, CK_RV> {
    let spki_der = public_key
        .to_spki()
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;

    let subject: Name = format!("CN=YubiKey PIV Slot {:x}", piv_slot as u8)
        .parse()
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;

    // This is a placeholder self-signed and meant to be
    // overwritten by a real CA-issued cert, so the serial doesn't need to
    // be unique
    let serial = SerialNumber::new(&[0x01]).map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let validity = Validity::from_now(core::time::Duration::new(10 * 365 * 24 * 3600, 0))
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;

    let builder = CertificateBuilder::new(RootProfile(subject), serial, validity, spki)
        .map_err(|_| CK_RV::from(CKR_GENERAL_ERROR))?;
    let signing_key = disposable_signing_key()?;
    let cert = builder
        .build::<_, p256::ecdsa::DerSignature>(&signing_key)
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
    require_so_login(slot.login_state)?;

    let Some(family) = parse_generate_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };
    yk_dbg!("generate_key_pair: mechanism {mechanism:#x} -> {family:?}");

    let pub_template = parse_template(family.clone(), public_key_template)?;
    let priv_template = parse_template(family.clone(), private_key_template)?;

    let slot_id = get_slot_id(&pub_template, &priv_template)?;
    check_key_type_consistency(&family, &pub_template, &priv_template)?;
    let key_algorithm = get_key_algorithm(&family, &pub_template)?;
    yk_dbg!(
        "generate_key_pair: slot {slot_id:?}, algorithm {key_algorithm:?}, pin policy {:?}, touch policy {:?}",
        priv_template.pin_policy,
        priv_template.touch_policy
    );

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    let public_key = piv
        .generate_key(
            slot_id,
            key_algorithm,
            priv_template.pin_policy.unwrap(),
            priv_template.touch_policy.unwrap(),
        )
        .map_err(piv_error_to_rv)?;

    let cert_der = build_placeholder_cert(slot_id, &public_key)?;
    piv.put_certificate(slot_id, &cert_der, false)
        .map_err(piv_error_to_rv)?;

    refresh_slot_objects(&mut slot.data.objects, piv, slot_id);

    let pub_handle = crate::piv_key_slot::PivObjectId::from_slot_class(
        crate::piv_key_slot::PivObjectClass::PublicKey,
        slot_id,
    ) as CK_OBJECT_HANDLE;
    let priv_handle = crate::piv_key_slot::PivObjectId::from_slot_class(
        crate::piv_key_slot::PivObjectClass::PrivateKey,
        slot_id,
    ) as CK_OBJECT_HANDLE;
    yk_dbg!("generate_key_pair: generated pub handle {pub_handle}, priv handle {priv_handle}");

    Ok((pub_handle, priv_handle))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            parse_generate_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Rsa)
        ));
        assert!(matches!(
            parse_generate_mechanism(CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Ec)
        ));
        assert!(matches!(
            parse_generate_mechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::Ed25519)
        ));
        assert!(matches!(
            parse_generate_mechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::X25519)
        ));
        assert!(matches!(
            parse_generate_mechanism(CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::MlDsa)
        ));
        assert!(matches!(
            parse_generate_mechanism(CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
            Some(KeyFamily::MlKem)
        ));
        assert!(parse_generate_mechanism(CKM_AES_CBC as CK_MECHANISM_TYPE).is_none());
    }

    #[test]
    fn get_slot_id_requires_at_least_one_cka_id() {
        let pub_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        let priv_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        assert_eq!(
            get_slot_id(&pub_t, &priv_t),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn get_slot_id_rejects_disagreement() {
        let pub_t = parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[1])]).unwrap();
        let priv_t = parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[2])]).unwrap();
        assert_eq!(
            get_slot_id(&pub_t, &priv_t),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn get_slot_id_accepts_agreement_and_maps_to_the_right_slot() {
        let pub_t = parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[3])]).unwrap();
        let priv_t = parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[3])]).unwrap();
        assert_eq!(get_slot_id(&pub_t, &priv_t), Ok(PivSlot::KeyManagement));
    }

    #[test]
    fn get_slot_id_accepts_id_on_only_one_template() {
        let pub_t = parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[3])]).unwrap();
        let priv_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        assert_eq!(get_slot_id(&pub_t, &priv_t), Ok(PivSlot::KeyManagement));
    }

    #[test]
    fn parse_template_rejects_attestation_and_out_of_range_ids() {
        assert_eq!(
            parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[25])]).err(),
            Some(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
        assert_eq!(
            parse_template(KeyFamily::Rsa, &[attr(CKA_ID, &[30])]).err(),
            Some(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn check_key_type_consistency_detects_mismatch() {
        let pub_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        let priv_t = parse_template(
            KeyFamily::Rsa,
            &[ulong_attr(CKA_KEY_TYPE, CKK_EC as CK_ULONG)],
        )
        .unwrap();
        assert_eq!(
            check_key_type_consistency(&KeyFamily::Rsa, &pub_t, &priv_t),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn check_key_type_consistency_accepts_matching_type() {
        let pub_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        let priv_t = parse_template(
            KeyFamily::Rsa,
            &[ulong_attr(CKA_KEY_TYPE, CKK_RSA as CK_ULONG)],
        )
        .unwrap();
        assert_eq!(
            check_key_type_consistency(&KeyFamily::Rsa, &pub_t, &priv_t),
            Ok(())
        );
    }

    #[test]
    fn get_key_algorithm_rsa_bit_sizes() {
        for (bits, expected) in [
            (1024, KeyAlgorithm::Rsa1024),
            (2048, KeyAlgorithm::Rsa2048),
            (3072, KeyAlgorithm::Rsa3072),
            (4096, KeyAlgorithm::Rsa4096),
        ] {
            let pub_t =
                parse_template(KeyFamily::Rsa, &[ulong_attr(CKA_MODULUS_BITS, bits)]).unwrap();
            assert_eq!(get_key_algorithm(&KeyFamily::Rsa, &pub_t), Ok(expected));
        }
    }

    #[test]
    fn get_key_algorithm_rejects_unsupported_rsa_bit_size() {
        let pub_t = parse_template(KeyFamily::Rsa, &[ulong_attr(CKA_MODULUS_BITS, 1536)]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Rsa, &pub_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn get_key_algorithm_requires_modulus_bits() {
        let pub_t = parse_template(KeyFamily::Rsa, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Rsa, &pub_t),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn get_key_algorithm_rejects_bad_public_exponent() {
        let pub_t = parse_template(
            KeyFamily::Rsa,
            &[
                ulong_attr(CKA_MODULUS_BITS, 2048),
                attr(CKA_PUBLIC_EXPONENT, &[0x03]),
            ],
        )
        .unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Rsa, &pub_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn get_key_algorithm_accepts_correct_public_exponent() {
        let pub_t = parse_template(
            KeyFamily::Rsa,
            &[
                ulong_attr(CKA_MODULUS_BITS, 2048),
                attr(CKA_PUBLIC_EXPONENT, &[0x01, 0x00, 0x01]),
            ],
        )
        .unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Rsa, &pub_t),
            Ok(KeyAlgorithm::Rsa2048)
        );
    }

    #[test]
    fn get_key_algorithm_ec_curve_oid_matching() {
        let p256_t = parse_template(KeyFamily::Ec, &[attr(CKA_EC_PARAMS, P256_CURVE_OID)]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Ec, &p256_t),
            Ok(KeyAlgorithm::EccP256)
        );
        let p384_t = parse_template(KeyFamily::Ec, &[attr(CKA_EC_PARAMS, P384_CURVE_OID)]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Ec, &p384_t),
            Ok(KeyAlgorithm::EccP384)
        );
        let bad_t =
            parse_template(KeyFamily::Ec, &[attr(CKA_EC_PARAMS, &[0x06, 0x01, 0x00])]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Ec, &bad_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn get_key_algorithm_requires_ec_params() {
        let pub_t = parse_template(KeyFamily::Ec, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Ec, &pub_t),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn get_key_algorithm_ed25519_defaults_from_mechanism_alone() {
        let ed_t = parse_template(KeyFamily::Ed25519, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::Ed25519, &ed_t),
            Ok(KeyAlgorithm::Ed25519)
        );
        let x_t = parse_template(KeyFamily::X25519, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::X25519, &x_t),
            Ok(KeyAlgorithm::X25519)
        );
    }

    #[test]
    fn get_key_algorithm_ml_dsa_parameter_sets() {
        for (param_set, expected) in [
            (CKP_ML_DSA_44, KeyAlgorithm::MlDsa44),
            (CKP_ML_DSA_65, KeyAlgorithm::MlDsa65),
            (CKP_ML_DSA_87, KeyAlgorithm::MlDsa87),
        ] {
            let pub_t = parse_template(
                KeyFamily::MlDsa,
                &[ulong_attr(CKA_PARAMETER_SET, param_set as CK_ULONG)],
            )
            .unwrap();
            assert_eq!(get_key_algorithm(&KeyFamily::MlDsa, &pub_t), Ok(expected));
        }
    }

    #[test]
    fn get_key_algorithm_ml_dsa_rejects_unknown_parameter_set() {
        let bad_t =
            parse_template(KeyFamily::MlDsa, &[ulong_attr(CKA_PARAMETER_SET, 0xFFFF)]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::MlDsa, &bad_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn get_key_algorithm_ml_dsa_requires_parameter_set() {
        let pub_t = parse_template(KeyFamily::MlDsa, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::MlDsa, &pub_t),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn get_key_algorithm_ml_kem_parameter_sets() {
        for (param_set, expected) in [
            (CKP_ML_KEM_512, KeyAlgorithm::MlKem512),
            (CKP_ML_KEM_768, KeyAlgorithm::MlKem768),
            (CKP_ML_KEM_1024, KeyAlgorithm::MlKem1024),
        ] {
            let pub_t = parse_template(
                KeyFamily::MlKem,
                &[ulong_attr(CKA_PARAMETER_SET, param_set as CK_ULONG)],
            )
            .unwrap();
            assert_eq!(get_key_algorithm(&KeyFamily::MlKem, &pub_t), Ok(expected));
        }
    }

    #[test]
    fn get_key_algorithm_ml_kem_rejects_unknown_parameter_set() {
        let bad_t =
            parse_template(KeyFamily::MlKem, &[ulong_attr(CKA_PARAMETER_SET, 0xFFFF)]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::MlKem, &bad_t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn get_key_algorithm_ml_kem_requires_parameter_set() {
        let pub_t = parse_template(KeyFamily::MlKem, &[]).unwrap();
        assert_eq!(
            get_key_algorithm(&KeyFamily::MlKem, &pub_t),
            Err(CKR_TEMPLATE_INCOMPLETE.into())
        );
    }

    #[test]
    fn parse_policies_defaults_to_token_default() {
        assert_eq!(
            parse_policies(None, None, None),
            Ok((PinPolicy::Default, TouchPolicy::Default))
        );
    }

    #[test]
    fn parse_policies_always_authenticate_forces_pin_always() {
        assert_eq!(
            parse_policies(None, None, Some(1)),
            Ok((PinPolicy::Always, TouchPolicy::Default))
        );
    }

    #[test]
    fn parse_policies_always_authenticate_conflicts_with_explicit_non_always_pin() {
        assert_eq!(
            parse_policies(Some(PinPolicy::Once as u8), None, Some(1)),
            Err(CKR_TEMPLATE_INCONSISTENT.into())
        );
    }

    #[test]
    fn build_placeholder_cert_produces_a_self_signed_cert_with_a_throwaway_signer() {
        use p256::ecdsa::signature::Verifier;

        // The "device" key embedded as the cert's subject — deliberately a
        // *different* key than the one that signs the cert, matching the
        // C reference's own placeholder-cert semantics (the throwaway
        // signer never corresponds to the subject's own key). Since
        // `build_placeholder_cert` draws its signing key from internal
        // randomness with no way to inject or recover it, this test can't
        // verify the signature against a known signer the way it could
        // when the signer was a parameter -- it instead checks the one
        // thing it *can* still verify from the outside: the subject's own
        // key must not be the one that produced the signature.
        let device_sk = p256::ecdsa::SigningKey::from_bytes((&[0x11u8; 32]).into()).unwrap();
        let device_vk = p256::ecdsa::VerifyingKey::from(&device_sk);
        let point = device_vk.to_sec1_point(false).as_bytes().to_vec();
        let public_key = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P256,
            point,
        });

        let cert_der = build_placeholder_cert(PivSlot::Authentication, &public_key).unwrap();
        assert!(cert_der.len() > 100);

        let parsed = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");
        assert_eq!(
            parsed.tbs_certificate().subject().to_string(),
            "CN=YubiKey PIV Slot 9a"
        );

        // The embedded subject key must be the *device's* key, not the signer's.
        assert_eq!(
            parsed
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .unwrap(),
            public_key.to_spki().unwrap()
        );

        // The signature must be a well-formed DER ECDSA signature...
        let tbs_der = parsed.tbs_certificate().to_der().expect("encode TBS");
        let cert_sig = p256::ecdsa::DerSignature::from_der(parsed.signature().raw_bytes())
            .expect("parse signature");
        // ...but must NOT verify against the device's own key -- the
        // throwaway signer is never the subject's key.
        assert!(
            device_vk.verify(&tbs_der, &cert_sig).is_err(),
            "the device key must not be able to verify the placeholder's throwaway signature"
        );
    }
}
