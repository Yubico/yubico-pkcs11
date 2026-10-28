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
use crate::derive::validate_derive_template;
use crate::objects::{find_private_key, find_public_key, store_secret_key};
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;
use yubikit::keys::{MlKemParameterSet, PublicKey};
use yubikit::piv::KeyType;

/// FIPS 203 Table 3's fixed ciphertext length per parameter set --
/// independent of any encapsulation randomness, so this can answer
/// `C_EncapsulateKey`'s length-query call without side effects.
fn ml_kem_ciphertext_len(parameter_set: MlKemParameterSet) -> Result<usize, CK_RV> {
    Ok(match parameter_set {
        MlKemParameterSet::MlKem512 => 768,
        MlKemParameterSet::MlKem768 => 1088,
        MlKemParameterSet::MlKem1024 => 1568,
        // yubikit::keys::MlKemParameterSet is #[non_exhaustive] -- every
        // variant that exists today is covered above, this only guards
        // future additions.
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

/// Encapsulates a fresh 32-byte shared secret against the raw ML-KEM
/// encapsulation-key bytes, returning `(ciphertext, shared_secret)`. Mirrors
/// the exact usage already proven against real hardware in `yubikit`'s own
/// device tests (`crates/yubikit/tests/device_tests/piv.rs`'s
/// `test_piv_mlkem768_decapsulate`, which encapsulates host-side with this
/// same crate and confirms the device decapsulates to the identical shared
/// secret). Three near-identical arms rather than one generic helper, since
/// `EncapsulationKey512`/`768`/`1024` are distinct marker types in the
/// `ml-kem` crate with no common byte-array-length bound to abstract over.
fn ml_kem_encapsulate(parameter_set: MlKemParameterSet, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CK_RV> {
    use ml_kem::{EncapsulationKey512, EncapsulationKey768, EncapsulationKey1024};

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;

    match parameter_set {
        MlKemParameterSet::MlKem512 => {
            let ek_bytes: &[u8; 800] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let ek = EncapsulationKey512::new(ek_bytes.into())
                .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&seed.into());
            Ok((ciphertext.as_slice().to_vec(), shared_secret.as_slice().to_vec()))
        }
        MlKemParameterSet::MlKem768 => {
            let ek_bytes: &[u8; 1184] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let ek = EncapsulationKey768::new(ek_bytes.into())
                .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&seed.into());
            Ok((ciphertext.as_slice().to_vec(), shared_secret.as_slice().to_vec()))
        }
        MlKemParameterSet::MlKem1024 => {
            let ek_bytes: &[u8; 1568] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let ek = EncapsulationKey1024::new(ek_bytes.into())
                .map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&seed.into());
            Ok((ciphertext.as_slice().to_vec(), shared_secret.as_slice().to_vec()))
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

fn check_mechanism(mechanism: CK_MECHANISM_TYPE, parameter: &[u8]) -> Result<(), CK_RV> {
    if mechanism as u32 != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    // PKCS#11 3.2 defines no mechanism parameter for CKM_ML_KEM.
    if !parameter.is_empty() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    Ok(())
}

/// The ciphertext length `encapsulate_key` will produce for `h_public_key`,
/// without performing the (randomized) encapsulation -- see
/// `pkcs11_common::backend::Backend::encapsulate_key_len`'s own doc comment
/// for why this needs to be side-effect-free.
pub fn encapsulate_key_len(slot: &mut Slot<PivBackend>, h_public_key: CK_OBJECT_HANDLE) -> Result<usize, CK_RV> {
    let Some((_, public_key)) = find_public_key(&slot.data.objects, h_public_key) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };
    let PublicKey::MlKem(k) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    ml_kem_ciphertext_len(k.parameter_set)
}

pub fn encapsulate_key(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    h_public_key: CK_OBJECT_HANDLE,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(Vec<u8>, CK_OBJECT_HANDLE), CK_RV> {
    check_mechanism(mechanism, parameter)?;
    validate_derive_template(template)?;

    let Some((piv_slot, public_key)) = find_public_key(&slot.data.objects, h_public_key) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };
    let PublicKey::MlKem(k) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };

    let (ciphertext, shared_secret) = ml_kem_encapsulate(k.parameter_set, &k.key)?;

    store_secret_key(&mut slot.data.objects, piv_slot, shared_secret);
    let handle = crate::objects::PivObjectId::PIV_SECRET_OBJ as CK_OBJECT_HANDLE;

    Ok((ciphertext, handle))
}

pub fn decapsulate_key(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    h_private_key: CK_OBJECT_HANDLE,
    ciphertext: &[u8],
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    check_mechanism(mechanism, parameter)?;
    validate_derive_template(template)?;

    // Matches derive.rs's own doc comment: no host-side login check here
    // either -- the device's AUTHENTICATE APDU rejects if the PIN hasn't
    // been verified.
    let Some((piv_slot, public_key)) = find_private_key(&slot.data.objects, h_private_key) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };
    let PublicKey::MlKem(_) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    let key_type =
        KeyType::try_from(&public_key.algorithm()).map_err(|_| CK_RV::from(CKR_KEY_TYPE_INCONSISTENT))?;

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
    let shared_secret = piv
        .calculate_secret(piv_slot, key_type, ciphertext)
        .map_err(piv_error_to_rv)?;

    store_secret_key(&mut slot.data.objects, piv_slot, shared_secret);

    Ok(crate::objects::PivObjectId::PIV_SECRET_OBJ as CK_OBJECT_HANDLE)
}
