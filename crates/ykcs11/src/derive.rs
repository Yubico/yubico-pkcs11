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


use crate::backend::{PivBackend, piv_error_to_rv};
use crate::objects::{find_private_key, store_secret_key};
use crate::template::find_attr;
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;
use yubikit::keys::PublicKey;
use yubikit::piv::KeyType;

/// `(key_type, expected raw public-point length)` for whatever
/// `calculate_secret` needs. A raw uncompressed EC point is `2*coord_len+1`
/// bytes; X25519's "point" is just its 32-byte public value. Matches
/// ykcs11.c:3732-3745's own `switch(algo)`.
fn ecdh_key_type(public_key: &PublicKey) -> Result<(KeyType, usize), CK_RV> {
    match public_key {
        PublicKey::Ec(k) => match k.curve {
            yubikit::keys::EcCurve::P256 => Ok((KeyType::EccP256, 65)),
            yubikit::keys::EcCurve::P384 => Ok((KeyType::EccP384, 97)),
            // PIV only ever generates/imports P-256/P-384 EC keys for ECDH;
            // any other curve here would mean the key was discovered oddly.
            _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
        },
        PublicKey::X25519(_) => Ok((KeyType::X25519, 32)),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

/// Reads a `CK_ECDH1_DERIVE_PARAMS` out of the mechanism's raw parameter
/// bytes and validates it exactly like ykcs11.c:3752-3762: `CKD_NULL` only,
/// no shared data, and a public point matching `expected_point_len`.
/// Returns the peer's raw public-point bytes.
fn resolve_ecdh1_derive_params(
    parameter: &[u8],
    expected_point_len: usize,
) -> Result<Vec<u8>, CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length just checked above; read_unaligned since a PKCS#11
    // caller isn't guaranteed to hand us a suitably aligned pointer (same
    // reasoning as pkcs11_common::mechanism's PSS/OAEP param readers).
    let params: CK_ECDH1_DERIVE_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_ECDH1_DERIVE_PARAMS) };

    if params.kdf != CKD_NULL as CK_ULONG
        || params.ulSharedDataLen != 0
        || params.pPublicData.is_null()
        || params.ulPublicDataLen as usize != expected_point_len
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }

    // SAFETY: `pPublicData`/`ulPublicDataLen` are a second caller-supplied
    // pointer+length pair, out-of-line from `parameter` itself -- same
    // trust boundary as `parameter` (valid for the duration of this call).
    Ok(unsafe {
        std::slice::from_raw_parts(params.pPublicData as *const u8, params.ulPublicDataLen as usize)
            .to_vec()
    })
}

/// Matches `validate_derive_key_attribute` (mechanisms.c:562-598): every
/// attribute the caller supplies in `phKey`'s template is checked against a
/// fixed expectation (the derived object is always a session
/// `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET`, always extractable) -- anything
/// else in the template is silently ignored, matching the C reference's
/// `default: break;` catch-all. `pub(crate)` since `encapsulate.rs` reuses
/// this verbatim for `C_EncapsulateKey`/`C_DecapsulateKey` -- no C reference
/// for those (PKCS#11 3.2), but they produce the exact same kind of object
/// `C_DeriveKey` does, so the same template expectations apply.
pub(crate) fn validate_derive_template(template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Result<(), CK_RV> {
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
    // Matches ykcs11.c:3723-3726's key-handle range check (via
    // `find_private_key`, the same lookup `C_SignInit`/`C_DecryptInit` use).
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
    use yubikit::keys::{EcCurve, EcPublicKey, Ed25519PublicKey, RsaKeySize, RsaPublicKey, X25519PublicKey};

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
        let p256 = PublicKey::Ec(EcPublicKey { curve: EcCurve::P256, point: vec![0x04; 65] });
        assert_eq!(ecdh_key_type(&p256), Ok((KeyType::EccP256, 65)));

        let p384 = PublicKey::Ec(EcPublicKey { curve: EcCurve::P384, point: vec![0x04; 97] });
        assert_eq!(ecdh_key_type(&p384), Ok((KeyType::EccP384, 97)));

        let x25519 = PublicKey::X25519(X25519PublicKey { key: vec![0u8; 32] });
        assert_eq!(ecdh_key_type(&x25519), Ok((KeyType::X25519, 32)));
    }

    #[test]
    fn ecdh_key_type_rejects_rsa_and_ed25519() {
        let rsa = PublicKey::Rsa(RsaPublicKey { key_size: RsaKeySize::Rsa2048, n: vec![], e: vec![] });
        assert_eq!(ecdh_key_type(&rsa), Err(CKR_KEY_TYPE_INCONSISTENT.into()));

        let ed25519 = PublicKey::Ed25519(Ed25519PublicKey { key: vec![0u8; 32] });
        assert_eq!(ecdh_key_type(&ed25519), Err(CKR_KEY_TYPE_INCONSISTENT.into()));
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
        assert_eq!(validate_derive_template(&t), Err(CKR_ATTRIBUTE_VALUE_INVALID.into()));
    }

    #[test]
    fn validate_derive_template_rejects_a_non_secret_key_class() {
        let t = [ulong_attr(CKA_CLASS, CKO_DATA as CK_ULONG)];
        assert_eq!(validate_derive_template(&t), Err(CKR_ATTRIBUTE_VALUE_INVALID.into()));
    }

    #[test]
    fn validate_derive_template_rejects_a_non_generic_secret_key_type() {
        let t = [ulong_attr(CKA_KEY_TYPE, CKK_AES as CK_ULONG)];
        assert_eq!(validate_derive_template(&t), Err(CKR_ATTRIBUTE_VALUE_INVALID.into()));
    }

    #[test]
    fn validate_derive_template_rejects_a_non_extractable_request() {
        let t = [bool_attr(CKA_EXTRACTABLE, false)];
        assert_eq!(validate_derive_template(&t), Err(CKR_ATTRIBUTE_VALUE_INVALID.into()));
    }
}
