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
