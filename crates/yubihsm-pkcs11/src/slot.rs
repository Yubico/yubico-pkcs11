// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

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
