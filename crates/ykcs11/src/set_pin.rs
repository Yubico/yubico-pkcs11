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
        // pOldPin is unused; pNewPin is the new management key, hex-encoded.
        let key_bytes = hex_decode(new_pin).ok_or(CK_RV::from(CKR_PIN_INVALID))?;
        let key_type = piv.management_key_type();
        let new_key =
            ManagementKey::new(key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_PIN_INVALID))?;
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
