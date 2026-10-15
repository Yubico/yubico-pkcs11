// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_SetPIN` backend logic for the YubiKey PIV module. Matches ykcs11.c's
//! own `C_SetPIN`/`token_change_pin` (ykcs11.c:870-918, token.c:241-283)
//! closely, including its overloaded semantics: PKCS#11 has no native
//! concept of a PIV PUK or of changing the management key, so the C
//! reference packs PIN change / PUK change / PIN-unblock-via-PUK /
//! management-key rotation into this single call, keyed off the *session's
//! current login state* (not an explicit parameter) plus a `"puk:"`/`"pin:"`
//! string-prefix convention on the old/new PIN bytes:
//!
//! - Logged in as **SO**: `pOldPin` is ignored; `pNewPin` is the new
//!   management key, hex-encoded (same convention `C_Login`'s SO branch
//!   already uses, see `authenticate_so`). Rotates the management key,
//!   keeping the same algorithm and touch policy the current one has.
//! - Logged in as **USER** (or not logged in at all -- this is also how
//!   PIN-change-without-prior-login and PIN-unblock work):
//!   - `pOldPin` starting with `"puk:"`:
//!     - `pNewPin` starting with `"pin:"` -> unblock the PIN using the PUK
//!       (both prefixes stripped).
//!     - otherwise -> change the PUK itself (an optional `"puk:"` prefix on
//!       `pNewPin` is stripped if present).
//!   - otherwise -> plain PIN change.
//!
//! Requires a R/W session on the *calling* session specifically
//! (ykcs11.c:895-899) -- unlike the SO-login RW-session check in
//! `backend.rs`'s `login`, which requires every open session on the slot to
//! be R/W, this only checks the one session making the call. Otherwise
//! there's no login-state gate at all: `token_change_pin` runs regardless
//! of whether the caller is logged in, same as this port.

use crate::backend::{PivBackend, piv_error_to_rv};
use pkcs11_common::backend::Slot;
use pkcs11_common::session::LoginState;
use pkcs11_common::util::hex_decode;
use pkcs11_sys::*;
use yubikit::piv::{ManagementKey, PivPin, TouchPolicy};

fn piv_pin(bytes: &[u8]) -> Result<PivPin, CK_RV> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
        .ok_or(CK_RV::from(CKR_PIN_LEN_RANGE))
}

const PUK_PREFIX: &[u8] = b"puk:";
const PIN_PREFIX: &[u8] = b"pin:";

enum UserPinRequest<'a> {
    ChangePin { old: &'a [u8], new: &'a [u8] },
    ChangePuk { old: &'a [u8], new: &'a [u8] },
    UnblockPin { puk: &'a [u8], new_pin: &'a [u8] },
}

/// Matches token.c:267-281's `CKU_USER` branch dispatch exactly.
fn classify_user_pin_request<'a>(old_pin: &'a [u8], new_pin: &'a [u8]) -> UserPinRequest<'a> {
    match old_pin.strip_prefix(PUK_PREFIX) {
        Some(puk) => match new_pin.strip_prefix(PIN_PREFIX) {
            Some(new_pin) => UserPinRequest::UnblockPin { puk, new_pin },
            None => UserPinRequest::ChangePuk {
                old: puk,
                new: new_pin.strip_prefix(PUK_PREFIX).unwrap_or(new_pin),
            },
        },
        None => UserPinRequest::ChangePin { old: old_pin, new: new_pin },
    }
}

pub fn set_pin(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    old_pin: &[u8],
    new_pin: &[u8],
) -> Result<(), CK_RV> {
    // Matches ykcs11.c:895-899.
    let is_rw = slot
        .sessions
        .get(&h_session)
        .is_some_and(|s| s.flags & CKF_RW_SESSION as CK_FLAGS != 0);
    if !is_rw {
        return Err(CKR_SESSION_READ_ONLY.into());
    }

    let login_state = slot.login_state;
    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    if login_state == LoginState::SO {
        // Matches token.c:243-262: pOldPin is unused; pNewPin is the new
        // management key, hex-encoded.
        let key_bytes = hex_decode(new_pin).ok_or(CK_RV::from(CKR_PIN_INVALID))?;
        let key_type = piv.management_key_type();
        let new_key =
            ManagementKey::new(key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_PIN_INVALID))?;
        // "Same touch policy the old one had" (token.c:251) -- yubikit's
        // set_management_key only takes a bool, so this reads the current
        // touch requirement back from the device rather than hardcoding one.
        let require_touch = piv
            .get_management_key_metadata()
            .map(|m| matches!(m.touch_policy, TouchPolicy::Always | TouchPolicy::Cached))
            .unwrap_or(false);
        return piv.set_management_key(&new_key, require_touch).map_err(piv_error_to_rv);
    }

    match classify_user_pin_request(old_pin, new_pin) {
        UserPinRequest::ChangePin { old, new } => {
            let old = piv_pin(old)?;
            let new = piv_pin(new)?;
            piv.change_pin(&old, &new).map_err(piv_error_to_rv)
        }
        UserPinRequest::ChangePuk { old, new } => {
            let old = piv_pin(old)?;
            let new = piv_pin(new)?;
            piv.change_puk(&old, &new).map_err(piv_error_to_rv)
        }
        UserPinRequest::UnblockPin { puk, new_pin } => {
            let puk = piv_pin(puk)?;
            let new_pin = piv_pin(new_pin)?;
            piv.unblock_pin(&puk, &new_pin).map_err(piv_error_to_rv)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_user_pin_request_defaults_to_a_plain_pin_change() {
        match classify_user_pin_request(b"123456", b"654321") {
            UserPinRequest::ChangePin { old, new } => {
                assert_eq!(old, b"123456");
                assert_eq!(new, b"654321");
            }
            _ => panic!("expected ChangePin"),
        }
    }

    #[test]
    fn classify_user_pin_request_detects_a_puk_based_pin_unblock() {
        match classify_user_pin_request(b"puk:12345678", b"pin:654321") {
            UserPinRequest::UnblockPin { puk, new_pin } => {
                assert_eq!(puk, b"12345678");
                assert_eq!(new_pin, b"654321");
            }
            _ => panic!("expected UnblockPin"),
        }
    }

    #[test]
    fn classify_user_pin_request_detects_a_puk_change_with_a_bare_new_puk() {
        match classify_user_pin_request(b"puk:12345678", b"87654321") {
            UserPinRequest::ChangePuk { old, new } => {
                assert_eq!(old, b"12345678");
                assert_eq!(new, b"87654321");
            }
            _ => panic!("expected ChangePuk"),
        }
    }

    #[test]
    fn classify_user_pin_request_detects_a_puk_change_with_a_prefixed_new_puk() {
        match classify_user_pin_request(b"puk:12345678", b"puk:87654321") {
            UserPinRequest::ChangePuk { old, new } => {
                assert_eq!(old, b"12345678");
                assert_eq!(new, b"87654321");
            }
            _ => panic!("expected ChangePuk"),
        }
    }

    #[test]
    fn classify_user_pin_request_requires_the_prefix_at_the_very_start() {
        // Matches token.c:267's `ulOldLen >= 4 && strncmp(...)` check: a
        // short old PIN that merely happens to start similarly isn't
        // treated as a PUK operation.
        match classify_user_pin_request(b"puk", b"654321") {
            UserPinRequest::ChangePin { old, new } => {
                assert_eq!(old, b"puk");
                assert_eq!(new, b"654321");
            }
            _ => panic!("expected ChangePin"),
        }
    }
}
