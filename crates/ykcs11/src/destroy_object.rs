// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_DestroyObject` backend logic for the YubiKey PIV module. Scope
//! matches ykcs11.c's own `C_DestroyObject` (ykcs11.c:1693-1776) for the
//! object classes that matter in practice:
//!
//! - `CKO_SECRET_KEY` (the ECDH-derived `PIV_SECRET_OBJ` singleton from
//!   `C_DeriveKey`): pure host-side cleanup, no SO login, no device call --
//!   `get_sub_id` resolves it to sub_id 0, which skips the C reference's
//!   `if(id) {...}` device-deletion/SO-login branch entirely
//!   (ykcs11.c:1725-1742).
//! - `CKO_CERTIFICATE`/`CKO_PUBLIC_KEY`/the per-slot self-attestation
//!   certificate: requires SO (management key) login, then calls the
//!   device to clear that slot's certificate storage
//!   (`ActivePivSession::delete_certificate`, the Rust equivalent of
//!   `token_delete_cert`/`ykpiv_save_object(id, NULL, 0)`), then refreshes
//!   the slot's cached objects the same way `generate_key_pair`/
//!   `create_object` already do.
//! - `CKO_PRIVATE_KEY`: always rejected with `CKR_OBJECT_HANDLE_INVALID`.
//!   This matches the C reference exactly, if a little surprisingly:
//!   `get_sub_id` only resolves a real per-slot id for DATA/CERT/PUBK-range
//!   object ids (ykcs11.c's `piv_obj_id_t` enum ordering) -- private key
//!   ids fall outside that range and default to 0, which the C reference's
//!   own early guard (`id == 0 && hObject != PIV_SECRET_OBJ` ->
//!   `CKR_OBJECT_HANDLE_INVALID`, ykcs11.c:1716-1721) always rejects.
//!   Private keys simply can't be destroyed through this API in either
//!   implementation.
//!
//! One deliberate scope limitation beyond the C reference: `CKO_DATA`
//! objects (the fixed CCC/CHUID/Discovery/KeyHistory/etc. PIV metadata
//! objects) aren't destroyable here, even though ykcs11.c's
//! `token_delete_cert` is actually generic enough to support it (it's just
//! `ykpiv_save_object(tag, NULL, 0)` under a misleading name). These
//! objects aren't creatable through `C_CreateObject` either (see
//! `create_object.rs`), are essentially never targeted by real PKCS#11
//! clients, and wiping standard PIV card metadata through this path is a
//! real footgun if ever triggered by mistake -- so this port rejects it
//! with `CKR_ACTION_PROHIBITED` rather than reimplementing a rarely-used,
//! risk-asymmetric corner of the C reference.
//!
//! This port also deliberately does *not* replicate a side effect of the C
//! reference's own `get_sub_id` aliasing: destroying `PIV_SECRET_OBJ`
//! (sub_id 0) in ykcs11.c also wipes out any private-key object entries
//! from the in-memory list, since those happen to alias the same sub_id 0
//! default -- an accidental artifact of its flat array indexing, not
//! meaningful protocol behavior (same reasoning already documented for
//! `C_GetObjectSize`).

use crate::backend::{PivBackend, piv_error_to_rv};
use crate::objects::{ObjectClass, refresh_slot_objects};
use crate::template::require_so_login;
use pkcs11_common::backend::Slot;
use pkcs11_sys::*;

pub fn destroy_object(
    slot: &mut Slot<PivBackend>,
    _h_session: CK_SESSION_HANDLE,
    handle: CK_OBJECT_HANDLE,
) -> Result<(), CK_RV> {
    let Some(obj) = slot.data.objects.iter().find(|o| o.id as CK_OBJECT_HANDLE == handle) else {
        return Err(CKR_OBJECT_HANDLE_INVALID.into());
    };

    match obj.class {
        ObjectClass::SecretKey => {
            slot.data.objects.retain(|o| o.class != ObjectClass::SecretKey);
            Ok(())
        }
        ObjectClass::PrivateKey => Err(CKR_OBJECT_HANDLE_INVALID.into()),
        ObjectClass::Data => Err(CKR_ACTION_PROHIBITED.into()),
        ObjectClass::Certificate | ObjectClass::PublicKey | ObjectClass::AttestationCertificate => {
            require_so_login(slot.login_state)?;
            let piv_slot = obj.slot;

            let piv = slot
                .data
                .piv_session
                .as_mut()
                .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
            piv.delete_certificate(piv_slot).map_err(piv_error_to_rv)?;
            refresh_slot_objects(&mut slot.data.objects, piv, piv_slot);

            Ok(())
        }
    }
}
