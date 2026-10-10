// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_DecryptInit`/`C_DecryptUpdate`/`C_DecryptFinal` backend logic for the
//! YubiKey PIV module. RSA only — `decrypt_mechanism_init` hard-rejects
//! non-RSA keys (mechanisms.c:686-689); EC keys have no `C_Decrypt`
//! mechanism at all in PKCS#11 (ECDH key agreement goes through
//! `C_DeriveKey`/`CKM_ECDH1_DERIVE` instead, a separate and so-far
//! unimplemented feature).
//!
//! Structurally the mirror image of `sign.rs`: the device
//! (`ActivePivSession::decrypt`, matching `ykpiv_decipher_data`) performs
//! only the raw RSA private-key operation; this module's job is unwrapping
//! whatever padding scheme the mechanism specifies (`CKM_RSA_X_509`'s "no
//! padding" passthrough, `CKM_RSA_PKCS`'s EME-PKCS1-v1_5-DECODE, or
//! `CKM_RSA_PKCS_OAEP`'s EME-OAEP-DECODE — RFC 8017 §7.2.2/§7.1.2) around
//! that call.
//!
//! `C_DecryptUpdate` never produces incremental output for these mechanisms
//! — a bare RSA private-key operation has nothing to stream, unlike a block
//! cipher. The caller's ciphertext is simply buffered (same pattern as
//! `sign.rs`'s `Accumulator::Raw`) and the real work happens once, in
//! `decrypt_final`.

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
