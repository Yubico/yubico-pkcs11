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
use crate::objects::{find_private_key, store_secret_key};
use crate::template::find_attr;
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;
use yubikit::keys::PublicKey;
use yubikit::piv::KeyType;

fn ecdh_key_type(public_key: &PublicKey) -> Result<(KeyType, usize), CK_RV> {
    match public_key {
        PublicKey::Ec(k) => match k.curve {
            // A raw uncompressed EC point is `2 * point_len + 1` bytes
            yubikit::keys::EcCurve::P256 => Ok((KeyType::EccP256, 65)),
            yubikit::keys::EcCurve::P384 => Ok((KeyType::EccP384, 97)),
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        },
        PublicKey::X25519(_) => Ok((KeyType::X25519, 32)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

/// Parses `CK_ECDH1_DERIVE_PARAMS` and validates it
fn resolve_ecdh1_derive_params(
    parameter: &[u8],
    expected_point_len: usize,
) -> Result<Vec<u8>, CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length checked above; read_unaligned since a PKCS#11
    // caller isn't guaranteed to send a suitably aligned pointer
    let params: CK_ECDH1_DERIVE_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_ECDH1_DERIVE_PARAMS) };

    if params.kdf != CKD_NULL as CK_ULONG
        || params.ulSharedDataLen != 0
        || params.pPublicData.is_null()
        || params.ulPublicDataLen as usize != expected_point_len
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }

    // SAFETY: `pPublicData`/`ulPublicDataLen` are a caller-supplied
    // pointer+length pair, out-of-line from `parameter` itself.
    Ok(unsafe {
        std::slice::from_raw_parts(
            params.pPublicData as *const u8,
            params.ulPublicDataLen as usize,
        )
        .to_vec()
    })
}

pub(crate) fn validate_derive_template(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(), CK_RV> {
    if let Some(token) = find_attr(template, CKA_TOKEN).and_then(|b| b.first().copied()) {
        if token != 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
    }
    if let Some(class) = find_attr(template, CKA_CLASS) {
        let class = CK_ULONG::from_ne_bytes(
            class
                .try_into()
                .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
        );
        if class as u32 != CKO_SECRET_KEY {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
    }
    if let Some(key_type) = find_attr(template, CKA_KEY_TYPE) {
        let key_type = CK_ULONG::from_ne_bytes(
            key_type
                .try_into()
                .map_err(|_| CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
        );
        if key_type as u32 != CKK_GENERIC_SECRET {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
    }
    if let Some(extractable) = find_attr(template, CKA_EXTRACTABLE).and_then(|b| b.first().copied())
    {
        if extractable == 0 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
        }
    }
    Ok(())
}

pub fn derive_key(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    base_key_handle: CK_OBJECT_HANDLE,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    let Some((piv_slot, public_key)) = find_private_key(&slot.data.objects, base_key_handle) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };
    let (key_type, point_len) = ecdh_key_type(public_key)?;

    if mechanism != CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    let peer_point = resolve_ecdh1_derive_params(parameter, point_len)?;
    validate_derive_template(template)?;

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
    let secret = piv
        .calculate_secret(piv_slot, key_type, &peer_point)
        .map_err(piv_error_to_rv)?;

    store_secret_key(&mut slot.data.objects, piv_slot, secret);

    Ok(crate::objects::PivObjectId::PIV_SECRET_OBJ as CK_OBJECT_HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubikit::keys::{
        EcCurve, EcPublicKey, Ed25519PublicKey, RsaKeySize, RsaPublicKey, X25519PublicKey,
    };

    fn attr(ty: u32, value: &[u8]) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_vec())
    }
    fn ulong_attr(ty: u32, value: CK_ULONG) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, value.to_ne_bytes().to_vec())
    }
    fn bool_attr(ty: u32, value: bool) -> (CK_ATTRIBUTE_TYPE, Vec<u8>) {
        (ty as CK_ATTRIBUTE_TYPE, vec![value as u8])
    }

    #[test]
    fn ecdh_key_type_accepts_p256_and_p384_and_x25519() {
        let p256 = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P256,
            point: vec![0x04; 65],
        });
        assert_eq!(ecdh_key_type(&p256), Ok((KeyType::EccP256, 65)));

        let p384 = PublicKey::Ec(EcPublicKey {
            curve: EcCurve::P384,
            point: vec![0x04; 97],
        });
        assert_eq!(ecdh_key_type(&p384), Ok((KeyType::EccP384, 97)));

        let x25519 = PublicKey::X25519(X25519PublicKey { key: vec![0u8; 32] });
        assert_eq!(ecdh_key_type(&x25519), Ok((KeyType::X25519, 32)));
    }

    #[test]
    fn ecdh_key_type_rejects_rsa_and_ed25519() {
        let rsa = PublicKey::Rsa(RsaPublicKey {
            key_size: RsaKeySize::Rsa2048,
            n: vec![],
            e: vec![],
        });
        assert_eq!(ecdh_key_type(&rsa), Err(CKR_KEY_TYPE_INCONSISTENT.into()));

        let ed25519 = PublicKey::Ed25519(Ed25519PublicKey { key: vec![0u8; 32] });
        assert_eq!(
            ecdh_key_type(&ed25519),
            Err(CKR_KEY_TYPE_INCONSISTENT.into())
        );
    }

    fn params_bytes(params: CK_ECDH1_DERIVE_PARAMS) -> Vec<u8> {
        let size = std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>();
        unsafe { std::slice::from_raw_parts(&params as *const _ as *const u8, size).to_vec() }
    }

    #[test]
    fn resolve_ecdh1_derive_params_accepts_a_well_formed_p256_request() {
        let peer = vec![0x04u8; 65];
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_ULONG,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer.len() as CK_ULONG,
            pPublicData: peer.as_ptr() as *mut u8,
        };
        let bytes = params_bytes(params);
        assert_eq!(resolve_ecdh1_derive_params(&bytes, 65), Ok(peer));
    }

    #[test]
    fn resolve_ecdh1_derive_params_rejects_a_non_null_kdf() {
        let peer = vec![0x04u8; 65];
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_SHA1_KDF as CK_ULONG,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer.len() as CK_ULONG,
            pPublicData: peer.as_ptr() as *mut u8,
        };
        let bytes = params_bytes(params);
        assert_eq!(
            resolve_ecdh1_derive_params(&bytes, 65),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn resolve_ecdh1_derive_params_rejects_shared_data() {
        let peer = vec![0x04u8; 65];
        let shared = vec![0x01u8; 4];
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_ULONG,
            ulSharedDataLen: shared.len() as CK_ULONG,
            pSharedData: shared.as_ptr() as *mut u8,
            ulPublicDataLen: peer.len() as CK_ULONG,
            pPublicData: peer.as_ptr() as *mut u8,
        };
        let bytes = params_bytes(params);
        assert_eq!(
            resolve_ecdh1_derive_params(&bytes, 65),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn resolve_ecdh1_derive_params_rejects_a_mismatched_point_length() {
        let peer = vec![0x04u8; 65];
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_ULONG,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer.len() as CK_ULONG,
            pPublicData: peer.as_ptr() as *mut u8,
        };
        let bytes = params_bytes(params);
        // Base key is P-384 (expects a 97-byte point), caller sent 65.
        assert_eq!(
            resolve_ecdh1_derive_params(&bytes, 97),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn resolve_ecdh1_derive_params_rejects_a_null_public_data_pointer() {
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_ULONG,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: 65,
            pPublicData: std::ptr::null_mut(),
        };
        let bytes = params_bytes(params);
        assert_eq!(
            resolve_ecdh1_derive_params(&bytes, 65),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn resolve_ecdh1_derive_params_rejects_a_truncated_buffer() {
        assert_eq!(
            resolve_ecdh1_derive_params(&[0u8; 4], 65),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn validate_derive_template_accepts_an_empty_template() {
        assert_eq!(validate_derive_template(&[]), Ok(()));
    }

    #[test]
    fn validate_derive_template_accepts_the_expected_fixed_attributes() {
        let t = [
            bool_attr(CKA_TOKEN, false),
            ulong_attr(CKA_CLASS, CKO_SECRET_KEY as CK_ULONG),
            ulong_attr(CKA_KEY_TYPE, CKK_GENERIC_SECRET as CK_ULONG),
            bool_attr(CKA_EXTRACTABLE, true),
            // Unknown attributes are silently ignored, matching
            // validate_derive_key_attribute's `default: break;`.
            attr(CKA_LABEL, b"whatever"),
        ];
        assert_eq!(validate_derive_template(&t), Ok(()));
    }

    #[test]
    fn validate_derive_template_rejects_a_token_object_request() {
        let t = [bool_attr(CKA_TOKEN, true)];
        assert_eq!(
            validate_derive_template(&t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn validate_derive_template_rejects_a_non_secret_key_class() {
        let t = [ulong_attr(CKA_CLASS, CKO_DATA as CK_ULONG)];
        assert_eq!(
            validate_derive_template(&t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn validate_derive_template_rejects_a_non_generic_secret_key_type() {
        let t = [ulong_attr(CKA_KEY_TYPE, CKK_AES as CK_ULONG)];
        assert_eq!(
            validate_derive_template(&t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }

    #[test]
    fn validate_derive_template_rejects_a_non_extractable_request() {
        let t = [bool_attr(CKA_EXTRACTABLE, false)];
        assert_eq!(
            validate_derive_template(&t),
            Err(CKR_ATTRIBUTE_VALUE_INVALID.into())
        );
    }
}
