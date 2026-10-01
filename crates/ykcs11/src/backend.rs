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

impl Backend for PivBackend {
    type SlotData = PivSlotData;
    type SessionData = ();
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

    fn new_session_data(_slot: &mut PivSlotData, _handle: CK_SESSION_HANDLE, _flags: CK_FLAGS) {}

    fn login(
        slot: &mut Slot<Self>,
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
        // is in progress on the calling session (ykcs11.c:1290-1296). This
        // module doesn't track per-session crypto operations yet
        // (C_SignInit/C_DecryptInit aren't implemented), so one can never
        // legitimately be "in progress" — matches what the C module itself
        // returns in that same state.
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            return Err(CKR_USER_TYPE_INVALID.into());
        }

        let piv = slot
            .data
            .piv_session
            .as_mut()
            .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

        // Safe to narrow: already validated above to be CKU_SO or CKU_USER,
        // both small enough to round-trip through u32 (CK_USER_TYPE is only
        // ever u32 or u64 depending on platform).
        match user_type as u32 {
            CKU_USER => {
                // Matches ykcs11.c:1301-1314.
                if slot.login_state == LoginState::User {
                    return Err(CKR_USER_ALREADY_LOGGED_IN.into());
                }
                if slot.login_state == LoginState::SO {
                    return Err(CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into());
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
}

/// Sentinels matching `token_login` (token.c:302-303): a request for
/// biometric-only verification, and a request to skip verification
/// entirely (e.g. when already verified out-of-band).
const VERIFY_BIO: &[u8] = b"VERIFY_BIO";
const VERIFY_NONE: &[u8] = b"VERIFY_NONE";

/// Maps a failed PIN/UV verification the same way the C module's
/// `yrc_to_rv` maps `YKPIV_WRONG_PIN`/`YKPIV_PIN_LOCKED` (utils.c:181,187):
/// out of retries is a lockout, otherwise just an incorrect PIN.
fn pin_error_to_rv(e: PivError) -> CK_RV {
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
            .map_err(pin_error_to_rv);
    }
    if pin == VERIFY_NONE {
        return Ok(());
    }

    let piv_pin = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
        .ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
    piv.verify_pin(&piv_pin).map_err(pin_error_to_rv)
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
        piv.verify_uv(false, false).map_err(pin_error_to_rv)?;
    } else if pin == VERIFY_NONE {
        return Ok(());
    } else if let Some(piv_pin) = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
    {
        piv.verify_pin(&piv_pin).map_err(pin_error_to_rv)?;
    } else {
        // Not a PIN-length value: must be the literal hex-encoded
        // management key.
        let key_bytes = pkcs11_common::util::hex_decode(pin).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
        let key_type = piv.management_key_type();
        let key =
            ManagementKey::new(key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_ARGUMENTS_BAD))?;
        return piv.authenticate(&key).map_err(|e| match e {
            // Matches token.c:366-367: a rejected response from the device
            // means the supplied key was wrong.
            PivError::InvalidData(_) => CK_RV::from(CKR_PIN_INCORRECT),
            other => pin_error_to_rv(other),
        });
    }

    Err(CKR_USER_PIN_NOT_INITIALIZED.into())
}

pub static G_ENGINE: Engine<PivBackend> = Engine::new();
