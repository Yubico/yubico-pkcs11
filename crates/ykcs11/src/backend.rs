// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! [`pkcs11_common::backend::Backend`] impl for the YubiKey PIV module.

use crate::piv_slot::PivSlotData;
use pkcs11_common::backend::{Backend, Engine, LibraryInfo, ModuleState, Slot, SlotInfo, TokenInfo};
use pkcs11_sys::*;

const YKCS11_MANUFACTURER: &str = "Yubico (www.yubico.com)";
const YKCS11_LIBDESC: &str = "PKCS#11 PIV Library (SP-800-73)";
const YKCS11_VERSION_MAJOR: u8 = 1;
const YKCS11_VERSION_MINOR: u8 = 0;

pub struct PivBackend;

impl Backend for PivBackend {
    type SlotData = PivSlotData;
    type SessionData = ();
    type ModuleData = ();

    fn library_info() -> LibraryInfo {
        LibraryInfo {
            manufacturer_id: YKCS11_MANUFACTURER,
            library_description: YKCS11_LIBDESC,
            library_version: (YKCS11_VERSION_MAJOR, YKCS11_VERSION_MINOR),
            cryptoki_version: (3, 0),
        }
    }

    fn initialize(reserved: Option<&str>) -> Result<((), Vec<PivSlotData>), CK_RV> {
        if reserved.is_some() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        // Slots are discovered lazily by `refresh_slots` on the first
        // `C_GetSlotList` call, same as the original ykpiv-backed module.
        Ok(((), Vec::new()))
    }

    fn refresh_slots(state: &mut ModuleState<Self>) -> Result<(), CK_RV> {
        crate::discovery::refresh_slots(state)
    }

    fn is_present(data: &PivSlotData) -> bool {
        data.token_present
    }

    fn slot_info(_slot_id: CK_SLOT_ID, data: &PivSlotData) -> SlotInfo {
        SlotInfo {
            description: data.reader_name.clone(),
            manufacturer_id: YKCS11_MANUFACTURER.to_string(),
            hardware_version: data.hw_version,
            firmware_version: data.fw_version,
        }
    }

    fn token_info(data: &mut PivSlotData) -> Option<TokenInfo> {
        if !data.token_present {
            return None;
        }

        // Query live PIN retry state before taking the immutable borrow
        // below.
        let retry_flags: CK_FLAGS = match data.piv_session.as_mut() {
            Some(piv) => match piv.get_pin_attempts() {
                Ok(0) => CKF_USER_PIN_LOCKED as CK_FLAGS,
                Ok(1) => CKF_USER_PIN_FINAL_TRY as CK_FLAGS,
                Ok(2) => CKF_USER_PIN_COUNT_LOW as CK_FLAGS,
                Ok(_) => 0,
                Err(_) => 0,
            },
            None => 0,
        };

        let t = data.token_info.as_ref()?;
        Some(TokenInfo {
            label: t.label.clone(),
            manufacturer_id: t.manufacturer.clone(),
            model: t.model.clone(),
            serial_number: t.serial.clone(),
            min_pin_len: t.min_pin_len,
            max_pin_len: t.max_pin_len,
            hardware_version: (1, 0),
            firmware_version: (t.fw_version_major, t.fw_version_minor),
            extra_flags: retry_flags,
        })
    }

    fn max_sessions(_data: &PivSlotData) -> Option<usize> {
        Some(crate::piv_slot::YKCS11_MAX_SESSIONS)
    }

    fn new_session_data(_slot: &mut PivSlotData, _handle: CK_SESSION_HANDLE, _flags: CK_FLAGS) {}

    fn login(_slot: &mut Slot<Self>, _user_type: CK_USER_TYPE, _pin: &[u8]) -> Result<(), CK_RV> {
        // TODO: call yubikit to verify the PIN / authenticate the
        // management key. Not yet wired up — matches the current
        // CKR_FUNCTION_NOT_SUPPORTED behavior.
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    fn logout(_slot: &mut Slot<Self>) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
}

pub static G_ENGINE: Engine<PivBackend> = Engine::new();
