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
use crate::discovery::ActivePivSession;
use pkcs11_common::backend::Slot;
use pkcs11_common::util::hex_decode;
use pkcs11_sys::*;
use yubikit::piv::{DEFAULT_MANAGEMENT_KEY, ManagementKey, ManagementKeyType, PivError, TouchPolicy};

/// Matches ykcs11.c:806-808/836-838: a rejected response from the device
/// means the supplied key was wrong.
fn authenticate_with_key(
    piv: &mut ActivePivSession,
    key_type: ManagementKeyType,
    key_bytes: &[u8],
) -> Result<(), CK_RV> {
    let key = ManagementKey::new(key_type, key_bytes).map_err(|_| CK_RV::from(CKR_PIN_INVALID))?;
    piv.authenticate(&key).map_err(|e| match e {
        PivError::InvalidData(_) => CK_RV::from(CKR_PIN_INCORRECT),
        other => piv_error_to_rv(other),
    })
}

pub fn init_token(slot: &mut Slot<PivBackend>, pin: &[u8]) -> Result<(), CK_RV> {
    let key_bytes = hex_decode(pin).ok_or(CK_RV::from(CKR_PIN_INVALID))?;

    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    // Matches ykcs11.c:805-812: prove the caller knows the current key
    // before allowing a wipe.
    let old_key_type = piv.management_key_type();
    authenticate_with_key(piv, old_key_type, &key_bytes)?;

    // "Same algorithm and touch policy the old one had" (ykcs11.c:849) --
    // captured now, before `reset()` wipes it, since yubikit's
    // `set_management_key` takes a plain bool rather than an "auto"
    // sentinel.
    let require_touch = piv
        .get_management_key_metadata()
        .map(|m| matches!(m.touch_policy, TouchPolicy::Always | TouchPolicy::Cached))
        .unwrap_or(false);

    piv.reset().map_err(piv_error_to_rv)?;

    // Matches ykcs11.c:836-842: re-authenticate with the now-restored
    // factory-default key.
    let default_key_type = piv.management_key_type();
    authenticate_with_key(piv, default_key_type, DEFAULT_MANAGEMENT_KEY)?;

    // Matches ykcs11.c:845-850: restore the original key, same algorithm
    // and touch policy it had before.
    let restored_key =
        ManagementKey::new(old_key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_PIN_INVALID))?;
    piv.set_management_key(&restored_key, require_touch)
        .map_err(piv_error_to_rv)?;

    // Everything on the device just got wiped -- repopulate wholesale
    // rather than trying to patch the existing (now entirely stale) cache.
    slot.data.objects = crate::objects::read_objects(piv);

    Ok(())
}
