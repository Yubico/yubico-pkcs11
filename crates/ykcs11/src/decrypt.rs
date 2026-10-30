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
use pkcs11_common::backend::Slot;
use pkcs11_common::decrypt::{eme_oaep_unpad, eme_pkcs1_v15_unpad};
use pkcs11_common::mechanism::{CryptMechanismKind, classify_crypt_mechanism, resolve_oaep_params};
use pkcs11_common::session::LoginState;
use pkcs11_common::sign::zero_pad;
use pkcs11_sys::*;
use yubikit::keys::PublicKey;
use yubikit::piv::Slot as PivSlot;

pub struct DecryptState {
    slot: PivSlot,
    modulus_len: usize,
    algo: DecryptAlgorithm,
    buf: Vec<u8>,
}

enum DecryptAlgorithm {
    /// `CKM_RSA_X_509`
    RsaX509,
    /// `CKM_RSA_PKCS`
    RsaPkcs1,
    /// `CKM_RSA_PKCS_OAEP`
    RsaOaep {
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        label: Vec<u8>,
    },
}

pub fn decrypt_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<(), CK_RV> {
    let Some((piv_slot, public_key)) =
        crate::objects::find_private_key(&slot.data.objects, key_handle)
    else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    if slot.login_state == LoginState::Public {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }

    let Some(mech_kind) = classify_crypt_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    let PublicKey::Rsa(k) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    let modulus_len = k.key_size.bit_len() / 8;

    let algo = match mech_kind {
        CryptMechanismKind::RsaX509 => DecryptAlgorithm::RsaX509,
        CryptMechanismKind::RsaPkcs1 => DecryptAlgorithm::RsaPkcs1,
        CryptMechanismKind::RsaOaep => {
            let (hash_mechanism, mgf_hash_mechanism, label) = resolve_oaep_params(parameter)?;
            DecryptAlgorithm::RsaOaep {
                hash_mechanism,
                mgf_hash_mechanism,
                label,
            }
        }
    };

    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    session.data.decrypt = Some(DecryptState {
        slot: piv_slot,
        modulus_len,
        algo,
        buf: Vec::new(),
    });

    Ok(())
}

pub fn decrypt_update(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    data: &[u8],
) -> Result<(), CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .decrypt
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.buf.extend_from_slice(data);
    Ok(())
}

pub fn decrypt_final(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .decrypt
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    // The ciphertext must be exactly one RSA block. `yubikit::piv::decrypt`
    // itself infers the key size purely from this length
    if state.buf.len() != state.modulus_len {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
    }

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
    let raw = piv
        .decrypt(state.slot, &state.buf)
        .map_err(piv_error_to_rv)?;
    let em = zero_pad(&raw, state.modulus_len)?;

    match state.algo {
        DecryptAlgorithm::RsaX509 => Ok(em),
        DecryptAlgorithm::RsaPkcs1 => eme_pkcs1_v15_unpad(&em),
        DecryptAlgorithm::RsaOaep {
            hash_mechanism,
            mgf_hash_mechanism,
            label,
        } => eme_oaep_unpad(&em, &label, hash_mechanism, mgf_hash_mechanism),
    }
}
