// Copyright 2026 Yubico AB

//! Backend-specific per-slot data for a PIV reader/slot discovered via
//! PC/SC. Everything generic (login state, open sessions) lives in
//! `pkcs11_common::backend::Slot`; this is just `Slot::data`.

use crate::discovery::ActivePivSession;
use pkcs11_sys::CK_ULONG;

pub const YKCS11_MAX_SESSIONS: usize = 16;

pub struct TokenInfo {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub fw_version_major: u8,
    pub fw_version_minor: u8,
    pub min_pin_len: CK_ULONG,
    pub max_pin_len: CK_ULONG,
}

/// One PC/SC reader slot. Persistent and append-only for the life of the
/// library: slots are looked up by `reader_name` and, once created, keep
/// their `CK_SLOT_ID` (their index in `ModuleState::slots`) even if the
/// reader/token temporarily disappears (`token_present` just goes false).
pub struct PivSlotData {
    pub reader_name: String,
    pub hw_version: (u8, u8),
    pub fw_version: (u8, u8),
    pub token_present: bool,
    pub token_info: Option<TokenInfo>,
    /// Live PC/SC connection + PIV application session for this slot, if
    /// currently connected. Established/refreshed by slot discovery
    /// (`C_GetSlotList`) and reused across sessions and PKCS#11 calls, same
    /// as `ykpiv_state` in the original C module.
    pub piv_session: Option<ActivePivSession>,
}

// Safety: `piv_session` (a PC/SC connection + PIV session) is only ever
// accessed while the slot's own `Mutex` is held.
unsafe impl Send for PivSlotData {}

impl PivSlotData {
    pub fn new(reader_name: String) -> Self {
        Self {
            hw_version: (1, 0),
            fw_version: (1, 0),
            reader_name,
            token_present: false,
            token_info: None,
            piv_session: None,
        }
    }

    /// Drop the live connection (if any) and reset token state. Mirrors
    /// `cleanup_slot`/disconnect handling in the C module, minus the
    /// cached-object bookkeeping (not yet ported). Login state is reset by
    /// the caller, since it lives at the generic `Slot` level.
    pub fn disconnect(&mut self) {
        self.piv_session = None;
        self.token_present = false;
        self.token_info = None;
    }
}
