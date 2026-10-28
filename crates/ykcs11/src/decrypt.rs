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
use pkcs11_common::backend::Slot;
use pkcs11_common::decrypt::{eme_oaep_unpad, eme_pkcs1_v15_unpad};
use pkcs11_common::mechanism::{CryptMechanismKind, classify_crypt_mechanism, resolve_oaep_params};
use pkcs11_common::session::LoginState;
use pkcs11_common::sign::zero_pad;
use pkcs11_sys::*;
use yubikit::keys::PublicKey;
use yubikit::piv::Slot as PivSlot;

/// Everything needed to finish a decrypt operation once `C_DecryptFinal` (or
/// `C_Decrypt`'s equivalent single-shot update+final) is called — stashed in
/// `PivBackend::SessionData` by `decrypt_init`, opaque to the shared engine.
pub struct DecryptState {
    slot: PivSlot,
    modulus_len: usize,
    algo: DecryptAlgorithm,
    buf: Vec<u8>,
}

enum DecryptAlgorithm {
    /// `CKM_RSA_X_509` — the raw RSA private-key operation's output, once
    /// zero-padded to `modulus_len`, *is* the plaintext; no unwrapping.
    RsaX509,
    /// `CKM_RSA_PKCS` — EME-PKCS1-v1_5-DECODE.
    RsaPkcs1,
    /// `CKM_RSA_PKCS_OAEP` — EME-OAEP-DECODE.
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
    let Some((piv_slot, public_key)) = crate::objects::find_private_key(&slot.data.objects, key_handle)
    else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    // Matches ykcs11.c's own re-check in C_DecryptInit, right after
    // key-handle validation and before mechanism setup (ykcs11.c:2365-2370)
    // — structurally identical to C_SignInit's equivalent check.
    if slot.login_state == LoginState::Public {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }

    let Some(mech_kind) = classify_crypt_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    // Matches decrypt_mechanism_init's CKK_RSA check (mechanisms.c:686-689)
    // — every decrypt mechanism is RSA-only.
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

pub fn decrypt_final(slot: &mut Slot<PivBackend>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .decrypt
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    // The ciphertext must be exactly one RSA block — `yubikit::piv::decrypt`
    // itself infers the key size purely from this length, so a wrong-length
    // input is caught explicitly here rather than surfacing as whatever
    // generic error that inference failure happens to produce.
    if state.buf.len() != state.modulus_len {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE.into());
    }

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
    let raw = piv.decrypt(state.slot, &state.buf).map_err(piv_error_to_rv)?;
    // The raw RSA private-key operation's output can be shorter than
    // `modulus_len` (a leading zero byte, as EME-PKCS1-v1_5/OAEP always
    // produce, doesn't round-trip through the device's own big-integer
    // representation) — zero-pad back out before any EME-decode math, which
    // assumes a fixed-width block.
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
