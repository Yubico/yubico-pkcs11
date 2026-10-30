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


// Debug output matching the C module's format:
//   [P11 - INF HH:MM:SS.UUUUUU] file.rs:line (func): message

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

pub static DBG_ENABLED: AtomicBool = AtomicBool::new(false);
pub static DINOUT_ENABLED: AtomicBool = AtomicBool::new(false);

// Colors are only enabled when building for Linux, empty strings everywhere else (including macOS).
#[cfg(target_os = "linux")]
pub const ANSI_RED: &str = "\x1b[31m";
#[cfg(target_os = "linux")]
pub const ANSI_YELLOW: &str = "\x1b[33m";
#[cfg(target_os = "linux")]
pub const ANSI_BLUE: &str = "\x1b[34m";
#[cfg(target_os = "linux")]
pub const ANSI_RESET: &str = "\x1b[0m";

#[cfg(not(target_os = "linux"))]
pub const ANSI_RED: &str = "";
#[cfg(not(target_os = "linux"))]
pub const ANSI_YELLOW: &str = "";
#[cfg(not(target_os = "linux"))]
pub const ANSI_BLUE: &str = "";
#[cfg(not(target_os = "linux"))]
pub const ANSI_RESET: &str = "";

pub fn dbg_init(dbg: bool, dinout: bool, _libdbg: bool, _debug_file: Option<&str>) {
    DBG_ENABLED.store(dbg || std::env::var("YUBIHSM_PKCS11_DBG").is_ok(), Ordering::SeqCst);
    DINOUT_ENABLED.store(dinout || std::env::var("YUBIHSM_PKCS11_DINOUT").is_ok(), Ordering::SeqCst);
    // TODO: redirect output to debug_file if specified
    // TODO: wire _libdbg / YUBIHSM_LIB_DBG into yubihsmrs's verbosity setting
}

#[inline]
pub fn is_dbg() -> bool {
    DBG_ENABLED.load(Ordering::Relaxed)
}

#[inline]
pub fn is_dinout() -> bool {
    DINOUT_ENABLED.load(Ordering::Relaxed)
}

/// Format a timestamp into HH:MM:SS.UUUUUU
fn timestamp() -> String {
    use std::time::UNIX_EPOCH;
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

/// Print a debug line in the format
/// [P11 - INF HH:MM:SS.UUUUUU] file:line (func): message
#[macro_export]
macro_rules! dbg_info {
    ($name:literal, $($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[{}P11 - INF{} {}] {}:{} ({}): {}",
                $crate::debug::ANSI_BLUE, $crate::debug::ANSI_RESET,
                $crate::debug::_timestamp(),
                file!(), line!(), $name,
                format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! dbg_err {
    ($name:literal, $($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[{}P11 - ERR{} {}] {}:{} ({}): {}",
                $crate::debug::ANSI_RED, $crate::debug::ANSI_RESET,
                $crate::debug::_timestamp(),
                file!(), line!(), $name,
                format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! dbg_warn {
    ($name:literal, $($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[{}P11 - WRN{} {}] {}:{} ({}): {}",
                $crate::debug::ANSI_YELLOW, $crate::debug::ANSI_RESET,
                $crate::debug::_timestamp(),
                file!(), line!(), $name,
                format!($($arg)*));
        }
    };
}

/// DIN/DOUT macros for function entry/exit tracing
#[macro_export]
macro_rules! din {
    ($name:literal) => {
        if $crate::debug::is_dinout() {
            eprintln!("[{}P11 - INF{} {}] {}:{} ({}): In",
                $crate::debug::ANSI_BLUE, $crate::debug::ANSI_RESET,
                $crate::debug::_timestamp(),
                file!(), line!(), $name);
        }
    };
}

#[macro_export]
macro_rules! dout {
    ($name:literal) => {
        if $crate::debug::is_dinout() {
            eprintln!("[{}P11 - INF{} {}] {}:{} ({}): Out",
                $crate::debug::ANSI_BLUE, $crate::debug::ANSI_RESET,
                $crate::debug::_timestamp(),
                file!(), line!(), $name);
        }
    };
}

// Helper exposed for macros (not public API)
#[doc(hidden)]
pub fn _timestamp() -> String {
    timestamp()
}