// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! [`pkcs11_common::backend::Backend`] impl for the YubiKey PIV module.

use crate::discovery::ActivePivSession;
use crate::piv_slot::PivSlotData;
use pkcs11_common::backend::{
    Backend, Engine, LibraryInfo, MechanismInfo, ModuleState, Slot, SlotInfo, TokenInfo,
};
use pkcs11_common::session::LoginState;
use pkcs11_sys::*;
use yubikit::piv::{ManagementKey, PivError, PivPin};

const YKCS11_MANUFACTURER: &str = "Yubico (www.yubico.com)";
const YKCS11_LIBDESC: &str = "PKCS#11 PIV Library (SP-800-73)";
const YKCS11_VERSION_MAJOR: u8 = 1;
const YKCS11_VERSION_MINOR: u8 = 0;

pub struct PivBackend;

/// Per-session state for whichever of `C_Sign*`/`C_Verify*` are currently in
/// progress — two independent slots, since PKCS#11 allows a sign operation
/// and a verify operation to be simultaneously active on the same session
/// (they're unrelated operation types, same as the engine's own independent
/// `digest_op`/`sign_op`/`verify_op` tracking). Each is opaque to the
/// engine, which only tracks whether *some* operation of each type is
/// active.
#[derive(Default)]
pub struct PivSessionData {
    pub sign: Option<crate::sign::SignState>,
    pub verify: Option<crate::verify::VerifyState>,
    pub encrypt: Option<crate::encrypt::EncryptState>,
    pub decrypt: Option<crate::decrypt::DecryptState>,
}

impl Backend for PivBackend {
    type SlotData = PivSlotData;
    type SessionData = PivSessionData;
    type ModuleData = ();

    fn library_info() -> LibraryInfo {
        LibraryInfo {
            manufacturer_id: YKCS11_MANUFACTURER,
            library_description: YKCS11_LIBDESC,
            library_version: (YKCS11_VERSION_MAJOR, YKCS11_VERSION_MINOR),
            cryptoki_version: (3, 0),
        }
    }

    fn initialize(reserved: Option<&str>) -> Result<((), Vec<PivSlotData>), CK_RV> {
        if reserved.is_some() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        // Slots are discovered lazily by `refresh_slots` on the first
        // `C_GetSlotList` call, same as the original ykpiv-backed module.
        Ok(((), Vec::new()))
    }

    fn refresh_slots(state: &mut ModuleState<Self>) -> Result<(), CK_RV> {
        crate::discovery::refresh_slots(state)
    }

    fn is_present(data: &PivSlotData) -> bool {
        data.token_present
    }

    fn slot_info(_slot_id: CK_SLOT_ID, data: &PivSlotData) -> SlotInfo {
        SlotInfo {
            description: data.reader_name.clone(),
            manufacturer_id: YKCS11_MANUFACTURER.to_string(),
            hardware_version: data.hw_version,
            firmware_version: data.fw_version,
        }
    }

    fn token_info(data: &mut PivSlotData) -> Option<TokenInfo> {
        if !data.token_present {
            return None;
        }

        // Query live PIN retry state before taking the immutable borrow
        // below.
        let retry_flags: CK_FLAGS = match data.piv_session.as_mut() {
            Some(piv) => match piv.get_pin_attempts() {
                Ok(0) => CKF_USER_PIN_LOCKED as CK_FLAGS,
                Ok(1) => CKF_USER_PIN_FINAL_TRY as CK_FLAGS,
                Ok(2) => CKF_USER_PIN_COUNT_LOW as CK_FLAGS,
                Ok(_) => 0,
                Err(_) => 0,
            },
            None => 0,
        };

        let t = data.token_info.as_ref()?;
        Some(TokenInfo {
            label: t.label.clone(),
            manufacturer_id: t.manufacturer.clone(),
            model: t.model.clone(),
            serial_number: t.serial.clone(),
            min_pin_len: t.min_pin_len,
            max_pin_len: t.max_pin_len,
            hardware_version: (1, 0),
            firmware_version: (t.fw_version_major, t.fw_version_minor),
            extra_flags: retry_flags,
        })
    }

    fn max_sessions(_data: &PivSlotData) -> Option<usize> {
        Some(crate::piv_slot::YKCS11_MAX_SESSIONS)
    }

    fn mechanism_list(_data: &PivSlotData) -> Vec<CK_MECHANISM_TYPE> {
        crate::mechanisms::token_mechanisms()
    }

    fn mechanism_info(data: &PivSlotData, mechanism: CK_MECHANISM_TYPE) -> Option<MechanismInfo> {
        let entry = crate::mechanisms::mechanism_table()
            .into_iter()
            .find(|e| e.mechanism == mechanism)?;

        // RSA key generation/operations above 2048 bits need firmware 5.7+;
        // on older keys the reported max clamps down, matching ykcs11.c's
        // is_version_compatible(..., 5, 7, 0) check.
        let mut max_key_size = entry.max_key_size;
        if max_key_size == 4096 {
            let fw_at_least_5_7 = data
                .token_info
                .as_ref()
                .is_some_and(|t| (t.fw_version_major, t.fw_version_minor) >= (5, 7));
            if !fw_at_least_5_7 {
                max_key_size = 2048;
            }
        }

        Some(MechanismInfo {
            min_key_size: entry.min_key_size,
            max_key_size,
            flags: entry.flags,
        })
    }

    fn new_session_data(
        slot: &mut PivSlotData,
        _handle: CK_SESSION_HANDLE,
        _flags: CK_FLAGS,
    ) -> PivSessionData {
        // Matches ykcs11.c:980's `n_objects == 0` guard: discover once per
        // slot, on the first session opened against it, and reuse for every
        // session after that.
        if slot.objects.is_empty() {
            if let Some(piv) = slot.piv_session.as_mut() {
                slot.objects = crate::objects::read_objects(piv);
            }
        }
        PivSessionData::default()
    }

    fn login(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        _username: &[u8],
    ) -> Result<(), CK_RV> {
        // ykcs11 has no C_LoginUser support (see backend.rs / ykcs11.c
        // stub) — `_username` is always empty here.
        // Matches ykcs11.c:1272-1277.
        if user_type != CKU_SO as CK_USER_TYPE
            && user_type != CKU_USER as CK_USER_TYPE
            && user_type != CKU_CONTEXT_SPECIFIC as CK_USER_TYPE
        {
            return Err(CKR_USER_TYPE_INVALID.into());
        }

        // CKU_CONTEXT_SPECIFIC is only legal while a sign/decrypt operation
        // is in progress on the calling session, to satisfy a key's
        // CKA_ALWAYS_AUTHENTICATE PIN-per-operation requirement
        // (ykcs11.c:1290-1296). `sign_op`/`decrypt_op` are the engine's own
        // generic bookkeeping (set active at *Init, cleared at *Final),
        // exactly mirroring the lifetime of the C reference's
        // `session->op_info.type`.
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            let op_in_progress = slot
                .sessions
                .get(&h_session)
                .is_some_and(|s| s.sign_op.active || s.decrypt_op.active);
            if !op_in_progress {
                return Err(CKR_USER_TYPE_INVALID.into());
            }
        }

        let piv = slot
            .data
            .piv_session
            .as_mut()
            .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

        // Safe to narrow: already validated above to be CKU_SO, CKU_USER, or
        // CKU_CONTEXT_SPECIFIC, all small enough to round-trip through u32
        // (CK_USER_TYPE is only ever u32 or u64 depending on platform).
        match user_type as u32 {
            CKU_USER | CKU_CONTEXT_SPECIFIC => {
                // Matches ykcs11.c:1301-1314 — these "already logged in"
                // rejections only apply to a plain CKU_USER login; the C
                // reference deliberately allows repeat CKU_CONTEXT_SPECIFIC
                // logins on top of an existing session (ykcs11.c:1300/1308).
                if user_type == CKU_USER as CK_USER_TYPE {
                    if slot.login_state == LoginState::User {
                        return Err(CKR_USER_ALREADY_LOGGED_IN.into());
                    }
                    if slot.login_state == LoginState::SO {
                        return Err(CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into());
                    }
                }

                verify_user_pin(piv, pin)?;

                // A context-specific login on top of an existing SO session
                // must not downgrade it back to User (ykcs11.c:1324).
                if slot.login_state == LoginState::Public {
                    slot.login_state = LoginState::User;
                }
            }
            CKU_SO => {
                // Matches ykcs11.c:1332-1353.
                if slot.login_state == LoginState::User {
                    return Err(CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into());
                }
                if slot.login_state == LoginState::SO {
                    return Err(CKR_USER_ALREADY_LOGGED_IN.into());
                }
                if slot
                    .sessions
                    .values()
                    .any(|s| s.flags & CKF_RW_SESSION as CK_FLAGS == 0)
                {
                    return Err(CKR_SESSION_READ_ONLY_EXISTS.into());
                }

                authenticate_so(piv, pin)?;

                slot.login_state = LoginState::SO;
            }
            _ => unreachable!("validated above"),
        }

        Ok(())
    }

    fn logout(slot: &mut Slot<Self>) -> Result<(), CK_RV> {
        // Matches ykcs11.c:1402-1408. No hardware call: unlike PIN
        // verification, there's no APDU to undo it — the module only ever
        // tracks its own login_state flag.
        if slot.login_state == LoginState::Public {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        slot.login_state = LoginState::Public;
        Ok(())
    }

    fn generate_random(_slot: &Slot<Self>, buf: &mut [u8]) -> Result<(), CK_RV> {
        // Matches do_rand_bytes (openssl_utils.c:39-46): host-side RNG, not
        // the YubiKey hardware — PIV has no "get random bytes" APDU, so the
        // C module never touches the card here either (just OpenSSL's
        // RAND_bytes); `getrandom` is our equivalent OS-backed source.
        getrandom::fill(buf).map_err(|_| CKR_FUNCTION_FAILED.into())
    }

    fn seed_random(_slot: &Slot<Self>, _seed: &[u8]) -> Result<(), CK_RV> {
        // Matches do_rand_seed (openssl_utils.c:39-46): mixes the caller's
        // bytes into OpenSSL's global RNG state and returns CKR_OK. `getrandom`
        // has no equivalent "stir in extra entropy" hook into the OS RNG, so
        // the seed is accepted (for API compatibility — real callers expect
        // CKR_OK here, same as the C module) but has no actual effect.
        Ok(())
    }

    fn object_handles(slot: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE> {
        crate::objects::object_handles(&slot.data.objects, slot.login_state != LoginState::Public)
    }

    fn get_one_attribute_value(
        data: &PivSlotData,
        handle: CK_OBJECT_HANDLE,
        attr_type: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>> {
        crate::objects::get_attribute(&data.objects, handle, attr_type)
    }

    fn sign_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        crate::sign::sign_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn sign_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::sign::sign_update(slot, h_session, data)
    }

    fn sign_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::sign::sign_final(slot, h_session)
    }

    fn verify_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::verify::verify_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn verify_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::verify::verify_update(slot, h_session, data)
    }

    fn verify_final(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        signature: &[u8],
    ) -> Result<(), CK_RV> {
        crate::verify::verify_final(slot, h_session, signature)
    }

    fn encrypt_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        crate::encrypt::encrypt_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn encrypt_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::encrypt::encrypt_update(slot, h_session, data)
    }

    fn encrypt_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::encrypt::encrypt_final(slot, h_session)
    }

    fn decrypt_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::decrypt::decrypt_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn decrypt_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::decrypt::decrypt_update(slot, h_session, data)
    }

    fn decrypt_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::decrypt::decrypt_final(slot, h_session)
    }

    fn generate_key_pair(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
        crate::generate::generate_key_pair(
            slot,
            h_session,
            mechanism,
            public_key_template,
            private_key_template,
        )
    }

    fn create_object(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::create_object::create_object(slot, h_session, template)
    }

    fn derive_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        base_key_handle: CK_OBJECT_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::derive::derive_key(slot, h_session, mechanism, parameter, base_key_handle, template)
    }

    fn destroy_object(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::destroy_object::destroy_object(slot, h_session, handle)
    }

    fn set_pin(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), CK_RV> {
        crate::set_pin::set_pin(slot, h_session, old_pin, new_pin)
    }

    fn init_token(slot: &mut Slot<Self>, pin: &[u8]) -> Result<(), CK_RV> {
        crate::init_token::init_token(slot, pin)
    }

    fn encapsulate_key_len(slot: &mut Slot<Self>, h_public_key: CK_OBJECT_HANDLE) -> Result<usize, CK_RV> {
        crate::encapsulate::encapsulate_key_len(slot, h_public_key)
    }

    fn encapsulate_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        h_public_key: CK_OBJECT_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(Vec<u8>, CK_OBJECT_HANDLE), CK_RV> {
        crate::encapsulate::encapsulate_key(slot, h_session, mechanism, parameter, h_public_key, template)
    }

    fn decapsulate_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        h_private_key: CK_OBJECT_HANDLE,
        ciphertext: &[u8],
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::encapsulate::decapsulate_key(
            slot,
            h_session,
            mechanism,
            parameter,
            h_private_key,
            ciphertext,
            template,
        )
    }
}

/// Sentinels matching `token_login` (token.c:302-303): a request for
/// biometric-only verification, and a request to skip verification
/// entirely (e.g. when already verified out-of-band).
const VERIFY_BIO: &[u8] = b"VERIFY_BIO";
const VERIFY_NONE: &[u8] = b"VERIFY_NONE";

/// Generic `PivError` -> `CK_RV` mapping, used anywhere a `yubikit::piv`
/// call can fail (PIN/UV verification, signing, ...) — mirrors the shape of
/// the C module's `yrc_to_rv` (utils.c:159-199), coarsened to match
/// `PivError`'s own, smaller set of variants: out of PIN retries is a
/// lockout (`YKPIV_PIN_LOCKED`), otherwise just an incorrect PIN
/// (`YKPIV_WRONG_PIN`).
pub(crate) fn piv_error_to_rv(e: PivError) -> CK_RV {
    match e {
        PivError::InvalidPin(0) => CKR_PIN_LOCKED.into(),
        PivError::InvalidPin(_) => CKR_PIN_INCORRECT.into(),
        PivError::NotSupported(_) => CKR_FUNCTION_NOT_SUPPORTED.into(),
        PivError::InvalidData(_) => CKR_ARGUMENTS_BAD.into(),
        PivError::Connection(_) => CKR_DEVICE_ERROR.into(),
        _ => CKR_GENERAL_ERROR.into(),
    }
}

/// Verify the PIV application PIN for a `CKU_USER` login, matching
/// `token_login`'s non-SO branch (token.c:305-335).
fn verify_user_pin(piv: &mut ActivePivSession, pin: &[u8]) -> Result<(), CK_RV> {
    if pin.is_empty() || pin == VERIFY_BIO {
        return piv
            .verify_uv(false, false)
            .map(|_| ())
            .map_err(piv_error_to_rv);
    }
    if pin == VERIFY_NONE {
        return Ok(());
    }

    let piv_pin = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
        .ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
    piv.verify_pin(&piv_pin).map_err(piv_error_to_rv)
}

/// Authenticate a `CKU_SO` login, matching `token_login`'s `CKU_SO` branch
/// (token.c:337-373).
///
/// Unlike the C module, there is no support here for a PIN-protected
/// management key stored on the device (`ykpiv_util_get_config` /
/// `YKPIV_CONFIG_MGM_PROTECTED`) — `yubikit` has no equivalent API — so
/// logging in as SO with just a PIN (rather than the literal hex-encoded
/// management key) fails with `CKR_USER_PIN_NOT_INITIALIZED`, the same code
/// the C module falls back to when no PIN-protected key is configured.
fn authenticate_so(piv: &mut ActivePivSession, pin: &[u8]) -> Result<(), CK_RV> {
    if pin.is_empty() || pin == VERIFY_BIO {
        piv.verify_uv(false, false).map_err(piv_error_to_rv)?;
    } else if pin == VERIFY_NONE {
        return Ok(());
    } else if let Some(piv_pin) = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
    {
        piv.verify_pin(&piv_pin).map_err(piv_error_to_rv)?;
    } else {
        // Not a PIN-length value: must be the literal hex-encoded
        // management key.
        let key_bytes =
            pkcs11_common::util::hex_decode(pin).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
        let key_type = piv.management_key_type();
        let key =
            ManagementKey::new(key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_ARGUMENTS_BAD))?;
        return piv.authenticate(&key).map_err(|e| match e {
            // Matches token.c:366-367: a rejected response from the device
            // means the supplied key was wrong.
            PivError::InvalidData(_) => CK_RV::from(CKR_PIN_INCORRECT),
            other => piv_error_to_rv(other),
        });
    }

    Err(CKR_USER_PIN_NOT_INITIALIZED.into())
}

pub static G_ENGINE: Engine<PivBackend> = Engine::new();

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_common::backend::{DecryptOp, EncryptOp, FindOp, Session, SignOp, VerifyOp};
    use std::collections::HashMap;

    fn slot_with_session(h_session: CK_SESSION_HANDLE, sign_active: bool, decrypt_active: bool) -> Slot<PivBackend> {
        let mut sessions = HashMap::new();
        sessions.insert(
            h_session,
            Session {
                handle: h_session,
                flags: 0,
                find_op: FindOp::default(),
                digest_op: None,
                sign_op: SignOp {
                    active: sign_active,
                    ..Default::default()
                },
                verify_op: VerifyOp::default(),
                encrypt_op: EncryptOp::default(),
                decrypt_op: DecryptOp {
                    active: decrypt_active,
                    ..Default::default()
                },
                data: PivSessionData::default(),
            },
        );
        Slot {
            login_state: LoginState::Public,
            sessions,
            data: crate::piv_slot::PivSlotData::new("test reader".to_string()),
        }
    }

    #[test]
    fn context_specific_login_rejected_with_no_operation_in_progress() {
        let mut slot = slot_with_session(1, false, false);
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_USER_TYPE_INVALID.into()));
    }

    #[test]
    fn context_specific_login_passes_the_gate_while_a_sign_operation_is_active() {
        let mut slot = slot_with_session(1, true, false);
        // No real `piv_session` is wired up in this test, so once the
        // CKU_CONTEXT_SPECIFIC gate is passed, the next thing `login` does
        // is look up `slot.data.piv_session` and fail with
        // CKR_TOKEN_NOT_PRESENT -- proving it got past the gate instead of
        // being rejected with CKR_USER_TYPE_INVALID.
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_TOKEN_NOT_PRESENT.into()));
    }

    #[test]
    fn context_specific_login_passes_the_gate_while_a_decrypt_operation_is_active() {
        let mut slot = slot_with_session(1, false, true);
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_TOKEN_NOT_PRESENT.into()));
    }

    #[test]
    fn context_specific_login_rejected_on_an_unknown_session_handle() {
        let mut slot = slot_with_session(1, true, true);
        let rv = PivBackend::login(&mut slot, 2, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_USER_TYPE_INVALID.into()));
    }
}
