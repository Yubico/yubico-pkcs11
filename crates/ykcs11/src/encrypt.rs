// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_EncryptInit`/`C_EncryptUpdate`/`C_EncryptFinal` backend logic for the
//! YubiKey PIV module. Same RSA-only mechanism set as `decrypt.rs`
//! (`CKM_RSA_X_509`/`CKM_RSA_PKCS`/`CKM_RSA_PKCS_OAEP` — `C_EncryptInit` and
//! `C_DecryptInit` share the identical `decrypt_mechanism_init` in the C
//! reference, mechanisms.c:684-729), but architecturally the mirror of
//! `verify.rs`, not `decrypt.rs`: encryption only needs a `CKO_PUBLIC_KEY`
//! object's public material, so there's no device round-trip and no login
//! check anywhere in `C_EncryptInit`/`C_Encrypt`/`C_EncryptUpdate`/
//! `C_EncryptFinal` (confirmed against ykcs11.c — same as `C_VerifyInit`'s
//! complete absence of a login_state check, ykcs11.c:3160-3228, and unlike
//! `C_DecryptInit`'s explicit `CKR_USER_NOT_LOGGED_IN` guard,
//! ykcs11.c:2365-2370).
//!
//! Because encryption output length is always exactly `modulus_len`
//! regardless of input (the padding scheme fills out whatever the message
//! doesn't use), it's computable at `encrypt_init` time from the key alone
//! — same as `sign.rs`, and unlike `decrypt.rs`'s `DecryptOp::pending`
//! lazy-cache (decrypt's output is *shorter* than `modulus_len` by a
//! variable, padding-dependent amount only known after unwrapping).

use pkcs11_common::backend::Slot;
use pkcs11_common::encrypt::{rsa_oaep_encrypt, rsa_pkcs1_encrypt, rsa_x509_encrypt};
use pkcs11_common::mechanism::{CryptMechanismKind, classify_crypt_mechanism, resolve_oaep_params};
use pkcs11_sys::*;
use yubikit::keys::PublicKey;

use crate::backend::PivBackend;

/// Everything needed to finish an encrypt operation once `C_EncryptFinal`
/// (or `C_Encrypt`'s equivalent single-shot update+final) is called —
/// stashed in `PivBackend::SessionData` by `encrypt_init`, opaque to the
/// shared engine.
pub struct EncryptState {
    n: Vec<u8>,
    e: Vec<u8>,
    modulus_len: usize,
    algo: EncryptAlgorithm,
    buf: Vec<u8>,
}

enum EncryptAlgorithm {
    RsaX509,
    RsaPkcs1,
    RsaOaep {
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        label: Vec<u8>,
    },
}

pub fn encrypt_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<CK_ULONG, CK_RV> {
    let Some(public_key) = crate::objects::find_verify_key(&slot.data.objects, key_handle) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    // No login check — matches ykcs11.c, which has none anywhere in the
    // C_Encrypt* family (same reasoning as C_Verify*: only public key
    // material is ever touched).

    let Some(mech_kind) = classify_crypt_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    // Matches decrypt_mechanism_init's CKK_RSA check (mechanisms.c:686-689),
    // shared by C_EncryptInit — every encrypt mechanism is RSA-only.
    let PublicKey::Rsa(k) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    let modulus_len = k.key_size.bit_len() / 8;

    let algo = match mech_kind {
        CryptMechanismKind::RsaX509 => EncryptAlgorithm::RsaX509,
        CryptMechanismKind::RsaPkcs1 => EncryptAlgorithm::RsaPkcs1,
        CryptMechanismKind::RsaOaep => {
            let (hash_mechanism, mgf_hash_mechanism, label) = resolve_oaep_params(parameter)?;
            EncryptAlgorithm::RsaOaep {
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
    session.data.encrypt = Some(EncryptState {
        n: k.n.clone(),
        e: k.e.clone(),
        modulus_len,
        algo,
        buf: Vec::new(),
    });

    Ok(modulus_len as CK_ULONG)
}

pub fn encrypt_update(
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
        .encrypt
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.buf.extend_from_slice(data);
    Ok(())
}

pub fn encrypt_final(slot: &mut Slot<PivBackend>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .encrypt
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    match state.algo {
        EncryptAlgorithm::RsaX509 => {
            rsa_x509_encrypt(&state.n, &state.e, state.modulus_len, &state.buf)
        }
        EncryptAlgorithm::RsaPkcs1 => {
            let ps_len = state
                .modulus_len
                .checked_sub(state.buf.len() + 3)
                .ok_or(CK_RV::from(CKR_DATA_LEN_RANGE))?;
            let ps = non_zero_random_bytes(ps_len)?;
            rsa_pkcs1_encrypt(&state.n, &state.e, state.modulus_len, &state.buf, &ps)
        }
        EncryptAlgorithm::RsaOaep {
            hash_mechanism,
            mgf_hash_mechanism,
            label,
        } => {
            let h_len = pkcs11_common::digest::DigestOp::new(hash_mechanism)?.output_len();
            let seed = random_bytes(h_len)?;
            rsa_oaep_encrypt(
                &state.n,
                &state.e,
                state.modulus_len,
                &state.buf,
                &label,
                &seed,
                hash_mechanism,
                mgf_hash_mechanism,
            )
        }
    }
}

/// `PS` for EME-PKCS1-v1_5-ENCODE must be random *and* non-zero (RFC 8017
/// §7.2.1 step 2(b)) — matches `RSA_padding_add_PKCS1_type_2`'s own
/// redraw-on-zero loop. `getrandom` is this module's OS-backed randomness
/// source, same as used for `C_GenerateRandom` and PSS's salt.
fn non_zero_random_bytes(len: usize) -> Result<Vec<u8>, CK_RV> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
    for byte in buf.iter_mut() {
        while *byte == 0 {
            getrandom::fill(std::slice::from_mut(byte)).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
        }
    }
    Ok(buf)
}

/// OAEP's seed has no non-zero requirement (unlike PKCS#1 v1.5's `PS`) — a
/// separate function (rather than reusing `non_zero_random_bytes`) to keep
/// that distinction explicit at the call site.
fn random_bytes(len: usize) -> Result<Vec<u8>, CK_RV> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
    Ok(buf)
}
