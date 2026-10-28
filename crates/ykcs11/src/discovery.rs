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


use crate::backend::PivBackend;
use crate::piv_slot::{PivSlotData, PivTokenInfo};
use parking_lot::Mutex;
use pkcs11_common::backend::{ModuleState, Slot};
use pkcs11_common::session::LoginState;
use pkcs11_common::yk_dbg;
use pkcs11_sys::{CK_RV, CK_ULONG};
use std::collections::HashSet;
use std::sync::Arc;
use yubikit::piv::PivSession;
use yubikit::platform::device::LocalYubiKeyDevice;
use yubikit::platform::pcsc::{list_readers_with_state, PcscSmartCardConnection};

/// A connected PIV application session, held per-slot for as long as the
/// token stays present. Equivalent to `ykpiv_state` in the C module.
pub type ActivePivSession = PivSession<PcscSmartCardConnection>;

const YKCS11_MANUFACTURER: &str = "Yubico (www.yubico.com)";
// Matches YKPIV_MIN_PIN_LEN / YKPIV_MAX_MGM_KEY_LEN in the original module.
const YKCS11_MIN_PIN_LEN: CK_ULONG = 6;
const YKCS11_MAX_PIN_LEN: CK_ULONG = 64;

/// Re-scan PC/SC readers and reconcile against `state.slots`. Must be called
/// with the module state already locked (the caller owns `&mut
/// ModuleState`); this mirrors `C_GetSlotList` holding `global_mutex` for
/// the whole reconciliation in the C module.
pub fn refresh_slots(state: &mut ModuleState<PivBackend>) -> Result<(), CK_RV> {
    let readers = list_readers_with_state().map_err(|e| {
        yk_dbg!("Unable to list readers: {}", e);
        let rv: CK_RV = pkcs11_sys::CKR_DEVICE_ERROR.into();
        rv
    })?;

    let mut matched: HashSet<usize> = HashSet::new();

    for (reader_name, card_present) in &readers {
        let idx = match state
            .slots
            .iter()
            .position(|s| s.lock().data.reader_name == *reader_name)
        {
            Some(i) => i,
            None => {
                yk_dbg!(
                    "Initializing slot {} for '{}'",
                    state.slots.len(),
                    reader_name
                );
                state
                    .slots
                    .push(Arc::new(Mutex::new(Slot::new(PivSlotData::new(
                        reader_name.clone(),
                    )))));
                state.slots.len() - 1
            }
        };

        matched.insert(idx);
        connect_slot(&state.slots[idx], reader_name, *card_present);
    }

    // Readers that vanished entirely (e.g. USB unplugged) keep their slot,
    // but lose their connection and CKF_TOKEN_PRESENT.
    for (idx, slot) in state.slots.iter().enumerate() {
        if matched.contains(&idx) {
            continue;
        }
        let mut s = slot.lock();
        if s.data.token_present {
            yk_dbg!("Disconnecting slot {} ('{}')", idx, s.data.reader_name);
        }
        s.data.disconnect();
        s.login_state = LoginState::Public;
    }

    Ok(())
}

/// Establish or refresh the connection for a single slot. A slot that is
/// already connected and still present is left alone (the cached connection
/// is trusted until an actual operation on it fails), matching `ykpiv_validate`
/// only reconnecting when the existing connection is stale.
fn connect_slot(slot: &Arc<Mutex<Slot<PivBackend>>>, reader_name: &str, card_present: bool) {
    let mut s = slot.lock();

    if !card_present {
        if s.data.token_present {
            yk_dbg!("Card removed from '{}'", reader_name);
        }
        s.data.disconnect();
        s.login_state = LoginState::Public;
        return;
    }

    if s.data.token_present && s.data.piv_session.is_some() {
        return;
    }

    let device = match LocalYubiKeyDevice::open_reader(reader_name) {
        Ok(d) => d,
        Err(e) => {
            yk_dbg!("Unable to read device info from '{}': {}", reader_name, e);
            s.data.disconnect();
            return;
        }
    };

    let conn = match device.open_smartcard() {
        Ok(c) => c,
        Err(e) => {
            yk_dbg!(
                "Unable to open smartcard connection to '{}': {}",
                reader_name,
                e
            );
            s.data.disconnect();
            return;
        }
    };

    let piv = match ActivePivSession::new(conn) {
        Ok(p) => p,
        Err((e, _conn)) => {
            yk_dbg!("Unable to open PIV session on '{}': {}", reader_name, e);
            s.data.disconnect();
            return;
        }
    };

    yk_dbg!("Connected slot to '{}'", reader_name);

    s.data.token_info = Some(build_token_info(&device));
    s.data.piv_session = Some(piv);
    s.data.token_present = true;
}

fn build_token_info(device: &LocalYubiKeyDevice) -> PivTokenInfo {
    let info = device.info();
    let serial = info.serial.map(|s| s.to_string()).unwrap_or_default();
    PivTokenInfo {
        label: format!("YubiKey PIV #{serial}"),
        manufacturer: YKCS11_MANUFACTURER.to_string(),
        model: yubikit::device::get_name(info),
        serial,
        fw_version_major: info.version.0,
        fw_version_minor: info.version.1,
        min_pin_len: YKCS11_MIN_PIN_LEN,
        max_pin_len: YKCS11_MAX_PIN_LEN,
    }
}
