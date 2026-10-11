// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! [`pkcs11_common::backend::Backend`] impl for the YubiHSM module.

use crate::config::{self, Config};
use crate::debug;
use crate::error::hsm_error_to_rv;
use crate::slot::YubiHsmSlotData;
use crate::{dbg_err, dbg_info, dbg_warn};
use pkcs11_common::backend::{
    Backend, Engine, LibraryInfo, MechanismInfo, Slot, SlotInfo, TokenInfo,
};
use pkcs11_common::session::LoginState;
use pkcs11_common::util::hex_decode;
use pkcs11_sys::*;
use yubihsmrs::object::ObjectAlgorithm;

const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const MANUFACTURER_ID: &str = "Yubico";
const LIBRARY_DESCRIPTION: &str = "YubiHSM PKCS#11 Library";

// yubihsm_pkcs11.c:49-50.
const YUBIHSM_PKCS11_MIN_PIN_LEN: usize = 8;
const YUBIHSM_PKCS11_MAX_PIN_LEN: usize = 64;

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
    // The authenticated device session is shared per-slot
    // (`YubiHsmSlotData::device_session`), not per PKCS#11 session — matches
    // `yubihsm_pkcs11_session` in the C module, which holds no session
    // handle of its own, only a pointer back to its slot.
    type SessionData = ();
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
        dbg_info!("initialize", "Initializing PKCS#11 module");

        if config.connectors.is_empty() {
            dbg_err!("initialize", "No connector defined");
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        if yubihsmrs::init().is_err() {
            dbg_warn!("initialize", "Failed to initialize libyubihsm");
            return Err(CKR_GENERAL_ERROR.into());
        }

        let mut slots = Vec::new();
        for connector_config in &config.connectors {
            let mut slot = YubiHsmSlotData::new(connector_config.clone());
            match slot.connect() {
                Ok(()) => dbg_info!("initialize", "Connected to {}", connector_config.url),
                Err(_) => dbg_warn!(
                    "initialize",
                    "Failed to connect to {}",
                    connector_config.url
                ),
            }
            slots.push(slot);
        }
        dbg_info!("initialize", "Found {} slot(s)", slots.len());

        Ok((config, slots))
    }

    fn finalize(_data: &mut Config) {
        dbg_info!("finalize", "Finalizing PKCS#11 module");
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

    fn mechanism_info(
        data: &YubiHsmSlotData,
        mechanism: CK_MECHANISM_TYPE,
    ) -> Option<MechanismInfo> {
        let algorithms = Self::device_algorithms(data)?;
        let info = crate::mechanisms::mechanism_info(&algorithms, mechanism)?;
        Some(MechanismInfo {
            min_key_size: info.min_key_size,
            max_key_size: info.max_key_size,
            flags: info.flags,
        })
    }

    fn new_session_data(_slot: &mut YubiHsmSlotData, _handle: CK_SESSION_HANDLE, _flags: CK_FLAGS) {
    }

    fn login(
        slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        username: &[u8],
    ) -> Result<(), CK_RV> {
        // Only CKU_USER exists in this module — there's no separate SO
        // role (yubihsm_pkcs11.c:6377-6380).
        if user_type != CKU_USER as CK_USER_TYPE {
            return Err(CKR_USER_TYPE_INVALID.into());
        }
        if pin.len() < YUBIHSM_PKCS11_MIN_PIN_LEN || pin.len() > YUBIHSM_PKCS11_MAX_PIN_LEN {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if username.is_empty() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        // Strip the '@' (asymmetric) / '#label#' (YubiKey ykhsmauth)
        // identity-scheme prefix, if any (yubihsm_pkcs11.c:6408-6436). Only
        // plain AES/symmetric auth (no prefix) is supported for now.
        let key_id_hex = match username[0] {
            b'@' => return Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
            b'#' => return Err(CKR_FUNCTION_NOT_SUPPORTED.into()),
            _ => username,
        };
        // What's left must be exactly the 4-hex-digit auth key ID
        // (yubihsm_pkcs11.c:6438-6456).
        if key_id_hex.len() != 4 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let key_id_bytes = hex_decode(key_id_hex).ok_or(CK_RV::from(CKR_PIN_INCORRECT))?;
        let key_id = u16::from_be_bytes([key_id_bytes[0], key_id_bytes[1]]);

        // Matches get_session(..., SESSION_NOT_AUTHENTICATED) failing with
        // CKR_USER_ALREADY_LOGGED_IN in C_LoginUser (yubihsm_pkcs11.c:6459).
        if slot.login_state == LoginState::User {
            return Err(CKR_USER_ALREADY_LOGGED_IN.into());
        }

        let hsm = slot
            .data
            .hsm
            .as_ref()
            .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;
        // yubihsmrs's session-establishing API takes the password as `&str`;
        // the C module treats it as opaque KDF input bytes with no encoding
        // requirement, so a non-UTF8 password is a (rare) capability gap
        // here, reported as bad arguments.
        let password = std::str::from_utf8(pin).map_err(|_| CK_RV::from(CKR_ARGUMENTS_BAD))?;

        // yubihsm_pkcs11.c:6542-6566 (symmetric/AES branch): create +
        // authenticate the session in one round trip.
        let session = hsm
            .establish_session(key_id, password, true)
            .map_err(hsm_error_to_rv)?;

        slot.data.device_session = Some(session);
        slot.login_state = LoginState::User;
        Ok(())
    }

    fn logout(slot: &mut Slot<Self>) -> Result<(), CK_RV> {
        // Matches get_session(..., SESSION_AUTHENTICATED) failing with
        // CKR_USER_NOT_LOGGED_IN in C_Logout (yubihsm_pkcs11.c:1348).
        if slot.login_state != LoginState::User {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }

        // Matches yubihsm_pkcs11.c:1353-1367: if closing the device session
        // fails, the module leaves its login state untouched rather than
        // pretending logout succeeded.
        if let Some(session) = slot.data.device_session.as_ref() {
            session.close().map_err(hsm_error_to_rv)?;
        }

        slot.data.device_session = None;
        slot.login_state = LoginState::Public;
        Ok(())
    }

    fn generate_random(slot: &Slot<Self>, buf: &mut [u8]) -> Result<(), CK_RV> {
        // Matches get_session(..., SESSION_AUTHENTICATED) in C_GenerateRandom
        // (yubihsm_pkcs11.c:6225) — unlike ykcs11, randomness comes from the
        // HSM hardware itself, over the authenticated session.
        if slot.login_state != LoginState::User {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }
        let session = slot
            .data
            .device_session
            .as_ref()
            .ok_or(CK_RV::from(CKR_USER_NOT_LOGGED_IN))?;
        let bytes = session.get_random(buf.len()).map_err(hsm_error_to_rv)?;
        buf.copy_from_slice(&bytes);
        Ok(())
    }

    // seed_random: not overridden — yubihsm_pkcs11.c's C_SeedRandom
    // unconditionally returns CKR_RANDOM_SEED_NOT_SUPPORTED, matching the
    // Backend trait's default.

    // Object enumeration isn't implemented for yubihsm-pkcs11 yet (its
    // dispatch.rs still wires C_FindObjects*/C_GetAttributeValue to the
    // shared not-yet-implemented stubs) — these are never actually called,
    // but the trait requires an impl.
    fn object_handles(_slot: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE> {
        Vec::new()
    }

    fn get_one_attribute_value(
        _data: &YubiHsmSlotData,
        _handle: CK_OBJECT_HANDLE,
        _attr_type: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>> {
        None
    }
}

pub static G_ENGINE: Engine<YubiHsmBackend> = Engine::new();
