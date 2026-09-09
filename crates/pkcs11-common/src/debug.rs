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