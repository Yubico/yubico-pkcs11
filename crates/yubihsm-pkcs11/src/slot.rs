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


//! Backend-specific per-slot data: one slot per configured connector.
//! Everything generic (login state, open sessions) lives in
//! `pkcs11_common::backend::Slot`; this is just `Slot::data`.

use crate::config::ConnectorConfig;
use pkcs11_sys::CK_RV;

pub struct YubiHsmSlotData {
    pub connector_config: ConnectorConfig,
    pub hsm: Option<yubihsmrs::YubiHsm>,
    /// The authenticated device session established by `C_Login`/
    /// `C_LoginUser`, shared by every PKCS#11 session open on this slot —
    /// matches `yubihsm_pkcs11_slot.device_session` in the C module (one
    /// session per slot, not per PKCS#11 session).
    pub device_session: Option<yubihsmrs::Session>,
}

impl YubiHsmSlotData {
    pub fn new(config: ConnectorConfig) -> Self {
        Self {
            connector_config: config,
            hsm: None,
            device_session: None,
        }
    }

    /// Connect to the YubiHSM. Called while building the initial slot list
    /// during `C_Initialize`.
    pub fn connect(&mut self) -> Result<(), CK_RV> {
        match yubihsmrs::YubiHsm::new(&self.connector_config.url) {
            Ok(hsm) => {
                self.hsm = Some(hsm);
                Ok(())
            }
            Err(_) => Err(pkcs11_sys::CKR_TOKEN_NOT_PRESENT.into()),
        }
    }

    pub fn is_present(&self) -> bool {
        self.hsm.is_some()
    }
}
