// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_InitToken` backend logic for the YubiKey PIV module. Matches
//! ykcs11.c's own `C_InitToken` (ykcs11.c:744-860) closely:
//!
//! `pPin` is always the hex-encoded PIV management key -- *not* a new key
//! to set, but the CURRENT one, used to authenticate before wiping the
//! device. `pLabel` is unused (PIV has no settable token label; the C
//! reference never references it either). The sequence:
//!
//! 1. Authenticate with the management key in `pPin` (proves the caller
//!    knows the current key before allowing a full wipe).
//! 2. Block the PIN and PUK, then reset the PIV application to factory
//!    defaults (`ActivePivSession::reset`, the Rust equivalent of
//!    `ykpiv_util_reset` -- wipes every key/cert on the device and resets
//!    the management key to the factory default; this bundles the C
//!    reference's manual "verify until blocked"/"unblock_pin until
//!    blocked" loops and the reset call itself into one method).
//! 3. Re-authenticate with the now-restored factory-default management key.
//! 4. Set the management key right back to what `pPin` supplied, preserving
//!    the algorithm and touch policy the OLD key had (ykcs11.c:849's "same
//!    algorithm and touch policy the old one had") -- captured *before* the
//!    reset wipes that information, since yubikit's `set_management_key`
//!    has no "AUTO" sentinel like `ykpiv_set_mgmkey3(..., AUTO, AUTO)` to
//!    recover it afterwards.
//! 5. Repopulate the slot's object cache from scratch, since every
//!    certificate/key the device had is now gone.
//!
//! No session-handle parameter: `C_InitToken` is a slot-level call in the
//! PKCS#11 spec, requiring zero open sessions on that slot (enforced
//! generically by `Engine::init_token`, matching ykcs11.c:773-779's
//! `CKR_SESSION_EXISTS` check -- not `Backend`-specific, since it's pure
//! session bookkeeping the engine already owns).

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
