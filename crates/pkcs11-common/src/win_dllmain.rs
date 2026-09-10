// Copyright 2026 Yubico AB

//! Windows-only: opts this module out of per-thread load notifications.
//!
//! A PKCS#11 module is always loaded via `LoadLibrary` by a foreign host
//! process (pkcs11-tool, a JVM via SunPKCS11/j2pkcs11.dll, etc.), never
//! statically linked at process startup. Windows sends `DLL_THREAD_ATTACH`
//! to *every loaded DLL* whenever *any* thread starts in the process — not
//! just threads that DLL created. The Rust runtime reacts to that
//! notification for its own per-thread bookkeeping, which assumes the
//! thread starting is one Rust knows about; for a thread the host process
//! spawned itself (e.g. a JVM GC/JIT thread, or whatever background thread),
//! that assumption doesn't hold and can corrupt
//! thread-local state (see rust-lang/rust#156277 for the same class of
//! issue). `DisableThreadLibraryCalls`, called as early as possible (our
//! own `DllMain`, at `DLL_PROCESS_ATTACH`), tells the loader to stop
//! sending this module thread-attach/detach notifications entirely,
//! sidestepping the problem instead of trying to survive it.

use std::ffi::c_void;

const DLL_PROCESS_ATTACH: u32 = 1;

unsafe extern "system" {
    fn DisableThreadLibraryCalls(h_lib_module: *mut c_void) -> i32;
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(hinst_dll);
        }
    }
    1 // TRUE
}
