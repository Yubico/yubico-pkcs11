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


//! Debug output matching both modules' format:
//!   ykcs11:      "DBG: file:line (func): message"
//!   yubihsm:     "[P11 - INF HH:MM:SS.UUUUUU] file:line (func): message"

use std::sync::atomic::{AtomicU8, Ordering};

pub static VERBOSE: AtomicU8 = AtomicU8::new(0);

pub fn set_verbose(level: u8) {
    VERBOSE.store(level, Ordering::SeqCst);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed) > 0
}

/// The raw verbosity tier (`YKCS11_DBG`'s value) — `0` is silent, `1` is the
/// usual `yk_dbg!`/debug-log tier, `2+` additionally enables trace-level
/// output (e.g. `yubikit`'s raw APDU traffic logging).
pub fn verbose_level() -> u8 {
    VERBOSE.load(Ordering::Relaxed)
}

/// Whether trace-tier output (`YKCS11_DBG>=2`) should be shown — distinct
/// from `is_verbose()`'s `YKCS11_DBG>=1` threshold since trace output (raw
/// APDU hex dumps) is far noisier than the regular debug messages.
pub fn is_trace_verbose() -> bool {
    verbose_level() >= 2
}

/// Timestamp for yubihsm-style debug output.
pub fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let usecs = now.subsec_micros();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}.{:06}", hours, minutes, seconds, usecs)
}

/// YubiHSM-style debug macro: [P11 - INF ...]
#[macro_export]
macro_rules! p11_dbg {
    ($($arg:tt)*) => {
        if $crate::debug::is_verbose() {
            eprintln!("[P11 - INF {}] {}:{}: {}",
                $crate::debug::timestamp(),
                file!(), line!(),
                format!($($arg)*));
        }
    };
}

/// YubiHSM-style error macro: [P11 - ERR ...]
#[macro_export]
macro_rules! p11_err {
    ($($arg:tt)*) => {
        if $crate::debug::is_verbose() {
            eprintln!("[P11 - ERR {}] {}:{}: {}",
                $crate::debug::timestamp(),
                file!(), line!(),
                format!($($arg)*));
        }
    };
}

/// ykcs11-style debug macro (matches DBG(...) in the C code)
#[macro_export]
macro_rules! yk_dbg {
    ($($arg:tt)*) => {
        if $crate::debug::is_verbose() {
            eprintln!("DBG: {}:{}: {}",
                file!(), line!(),
                format!($($arg)*));
        }
    };
}

/// DIN/DOUT for both modules
#[macro_export]
macro_rules! din {
    () => {
        if $crate::debug::is_verbose() {
            eprintln!("DBG: {}:{}: In", file!(), line!());
        }
    };
}

#[macro_export]
macro_rules! dout {
    () => {
        if $crate::debug::is_verbose() {
            eprintln!("DBG: {}:{}: Out", file!(), line!());
        }
    };
}