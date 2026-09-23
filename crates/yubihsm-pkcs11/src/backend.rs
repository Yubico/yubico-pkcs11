// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! [`pkcs11_common::backend::Backend`] impl for the YubiHSM module.

use crate::config::{self, Config};
use crate::debug;
use crate::slot::YubiHsmSlotData;
use crate::{dbg_info, dbg_warn};
use pkcs11_common::backend::{Backend, Engine, LibraryInfo, MechanismInfo, Slot, SlotInfo, TokenInfo};
use pkcs11_sys::*;
use yubihsmrs::object::ObjectAlgorithm;

const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const MANUFACTURER_ID: &str = "Yubico";
const LIBRARY_DESCRIPTION: &str = "YubiHSM PKCS#11 Library";

pub struct YubiHsmBackend;

impl YubiHsmBackend {
    /// The connected device's reported algorithm capabilities, or `None` if
    /// not connected / the query failed.
    fn device_algorithms(data: &YubiHsmSlotData) -> Option<Vec<ObjectAlgorithm>> {
        let hsm = data.hsm.as_ref()?;
        Some(hsm.get_device_info().ok()?.algorithms())
    }
}

impl Backend for YubiHsmBackend {
    type SlotData = YubiHsmSlotData;
    type SessionData = Option<yubihsmrs::Session>;
    type ModuleData = Config;

    fn library_info() -> LibraryInfo {
        LibraryInfo {
            manufacturer_id: MANUFACTURER_ID,
            library_description: LIBRARY_DESCRIPTION,
            library_version: (VERSION_MAJOR, VERSION_MINOR),
            cryptoki_version: (3, 0),
        }
    }

    fn initialize(reserved: Option<&str>) -> Result<(Config, Vec<YubiHsmSlotData>), CK_RV> {
        let config = config::resolve(reserved);

        debug::dbg_init(
            config.debug,
            config.dinout,
            config.libdebug,
            config.debug_file.as_deref(),
        );
        dbg_info!("Initializing PKCS#11 module");

        if yubihsmrs::init().is_err() {
            dbg_warn!("Failed to initialize libyubihsm");
            return Err(CKR_GENERAL_ERROR.into());
        }

        let mut slots = Vec::new();
        for connector_config in &config.connectors {
            let mut slot = YubiHsmSlotData::new(connector_config.clone());
            match slot.connect() {
                Ok(()) => dbg_info!("Connected to {}", connector_config.url),
                Err(_) => dbg_warn!("Failed to connect to {}", connector_config.url),
            }
            slots.push(slot);
        }
        dbg_info!("Found {} slot(s)", slots.len());

        Ok((config, slots))
    }

    fn finalize(_data: &mut Config) {
        dbg_info!("Finalizing PKCS#11 module");
        let _ = yubihsmrs::exit();
    }

    fn is_present(data: &YubiHsmSlotData) -> bool {
        data.is_present()
    }

    fn slot_info(slot_id: CK_SLOT_ID, _data: &YubiHsmSlotData) -> SlotInfo {
        SlotInfo {
            description: format!("YubiHSM Slot {}", slot_id),
            manufacturer_id: MANUFACTURER_ID.to_string(),
            hardware_version: (2, 0),
            firmware_version: (2, 0),
        }
    }

    fn token_info(data: &mut YubiHsmSlotData) -> Option<TokenInfo> {
        if !data.is_present() {
            return None;
        }
        Some(TokenInfo {
            label: "YubiHSM".to_string(),
            manufacturer_id: MANUFACTURER_ID.to_string(),
            model: "YubiHSM 2".to_string(),
            serial_number: "0000000000000000".to_string(),
            min_pin_len: 1,
            max_pin_len: 128,
            hardware_version: (2, 0),
            firmware_version: (2, 0),
            extra_flags: 0,
        })
    }

    fn mechanism_list(data: &YubiHsmSlotData) -> Vec<CK_MECHANISM_TYPE> {
        let Some(algorithms) = Self::device_algorithms(data) else {
            return Vec::new();
        };
        crate::mechanisms::mechanism_list(&algorithms)
    }

    fn mechanism_info(data: &YubiHsmSlotData, mechanism: CK_MECHANISM_TYPE) -> Option<MechanismInfo> {
        let algorithms = Self::device_algorithms(data)?;
        let info = crate::mechanisms::mechanism_info(&algorithms, mechanism)?;
        Some(MechanismInfo {
            min_key_size: info.min_key_size,
            max_key_size: info.max_key_size,
            flags: info.flags,
        })
    }

    fn new_session_data(
        _slot: &mut YubiHsmSlotData,
        _handle: CK_SESSION_HANDLE,
        _flags: CK_FLAGS,
    ) -> Option<yubihsmrs::Session> {
        None
    }

    fn login(_slot: &mut Slot<Self>, _user_type: CK_USER_TYPE, _pin: &[u8]) -> Result<(), CK_RV> {
        // TODO: parse "<4-digit-auth-key-id><password>" and establish a
        // yubihsmrs session. Not yet wired up — matches the current
        // CKR_FUNCTION_NOT_SUPPORTED behavior.
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    fn logout(_slot: &mut Slot<Self>) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
}

pub static G_ENGINE: Engine<YubiHsmBackend> = Engine::new();
