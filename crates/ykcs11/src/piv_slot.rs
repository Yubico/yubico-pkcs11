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


use crate::discovery::ActivePivSession;
use pkcs11_sys::CK_ULONG;

pub const YKCS11_MAX_SESSIONS: usize = 16;

pub struct PivTokenInfo {
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
    pub token_info: Option<PivTokenInfo>,
    /// Live PC/SC connection + PIV application session for this slot, if
    /// currently connected. Established/refreshed by slot discovery
    /// (`C_GetSlotList`) and reused across sessions and PKCS#11 calls, same
    /// as `ykpiv_state` in the original C module.
    pub piv_session: Option<ActivePivSession>,
    /// Cached PKCS#11 certificate/key objects, populated once on the first
    /// `C_OpenSession` (see `PivBackend::new_session_data`) and shared by
    /// every session on this slot — matches ykcs11.c's `slot->objects[]`
    /// (`n_objects == 0` guard, ykcs11.c:980).
    pub objects: Vec<crate::objects::PivObject>,
}

impl PivSlotData {
    pub fn new(reader_name: String) -> Self {
        Self {
            hw_version: (1, 0),
            fw_version: (1, 0),
            reader_name,
            token_present: false,
            token_info: None,
            piv_session: None,
            objects: Vec::new(),
        }
    }

    /// Drop the live connection (if any) and reset token state. Mirrors
    /// `cleanup_slot`/disconnect handling in the C module. Login state is
    /// reset by the caller, since it lives at the generic `Slot` level.
    /// Clearing `objects` here (unlike the C module, which only clears its
    /// cache when the last session on a slot closes) means a card swapped
    /// in the same reader always gets freshly discovered, not stale cached
    /// certs from whatever was there before.
    pub fn disconnect(&mut self) {
        self.piv_session = None;
        self.token_present = false;
        self.token_info = None;
        self.objects.clear();
    }
}
