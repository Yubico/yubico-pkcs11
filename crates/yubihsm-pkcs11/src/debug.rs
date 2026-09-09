// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! Debug output matching the C module's format:
//!   [P11 - INF HH:MM:SS.UUUUUU] file.rs:line (func): message

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

pub static DBG_ENABLED: AtomicBool = AtomicBool::new(false);
pub static DINOUT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize debug settings from config.
pub fn dbg_init(dbg: bool, dinout: bool, _libdbg: bool, _debug_file: Option<&str>) {
    DBG_ENABLED.store(dbg, Ordering::SeqCst);
    DINOUT_ENABLED.store(dinout, Ordering::SeqCst);
    // TODO: redirect output to debug_file if specified
}

#[inline]
pub fn is_dbg() -> bool {
    DBG_ENABLED.load(Ordering::Relaxed)
}

#[inline]
pub fn is_dinout() -> bool {
    DINOUT_ENABLED.load(Ordering::Relaxed)
}

/// Format a timestamp like the C code: HH:MM:SS.UUUUUU
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

/// Print a debug line matching C format:
/// [P11 - INF HH:MM:SS.UUUUUU] file:line (func): message
#[macro_export]
macro_rules! dbg_info {
    ($($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[P11 - INF {}] {}:{} ({}): {}",
                $crate::debug::_timestamp(),
                file!(), line!(), $crate::debug::_func_name(),
                format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! dbg_err {
    ($($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[P11 - ERR {}] {}:{} ({}): {}",
                $crate::debug::_timestamp(),
                file!(), line!(), $crate::debug::_func_name(),
                format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! dbg_warn {
    ($($arg:tt)*) => {
        if $crate::debug::is_dbg() {
            eprintln!("[P11 - WRN {}] {}:{} ({}): {}",
                $crate::debug::_timestamp(),
                file!(), line!(), $crate::debug::_func_name(),
                format!($($arg)*));
        }
    };
}

/// DIN/DOUT macros for function entry/exit tracing
#[macro_export]
macro_rules! din {
    () => {
        if $crate::debug::is_dinout() {
            eprintln!("[P11 - INF {}] {}:{} ({}): In",
                $crate::debug::_timestamp(),
                file!(), line!(), $crate::debug::_func_name());
        }
    };
}

#[macro_export]
macro_rules! dout {
    () => {
        if $crate::debug::is_dinout() {
            eprintln!("[P11 - INF {}] {}:{} ({}): Out",
                $crate::debug::_timestamp(),
                file!(), line!(), $crate::debug::_func_name());
        }
    };
}

// Helpers exposed for macros (not public API)
#[doc(hidden)]
pub fn _timestamp() -> String {
    timestamp()
}

#[doc(hidden)]
pub fn _func_name() -> &'static str {
    // Rust doesn't have __func__ at compile time in macros.
    // The caller's function name is embedded via file!/line!.
    // We return a placeholder; the real function context comes from the call site.
    ""
}