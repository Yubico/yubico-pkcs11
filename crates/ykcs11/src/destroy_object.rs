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
