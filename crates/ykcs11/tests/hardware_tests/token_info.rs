// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_GetTokenInfo` hardware coverage -- the Rust equivalent of
//! `ykcs11_tests.c`'s `test_token_info()`.

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

/// Unlike `ykcs11_tests.c`'s `test_token_info()`, this doesn't exact-match
/// `CK_TOKEN_INFO.model` against `"YubiKey YK4"`/`"YK5"`/`"NEO"` (modern
/// `yubikit::device::get_name` output like `"YubiKey 5 NFC"` doesn't match
/// those literals) -- it checks the same looser `"YubiKey"` prefix the C
/// test itself checks first. Capability differences between firmware
/// versions (PIV slot count, available mechanisms, ...) are each handled by
/// the specific test that cares, via `firmware_at_least`, rather than by a
/// single model/generation label derived here.
#[test]
fn hardware_token_info() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_token_info: set {RUN_ENV_VAR}=1 to run \
             (destructive -- see this crate's module doc comment)"
        );
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
    assert_ok(rv, "C_Initialize");

    let slot_id = first_token_present_slot();
    // token_init(slot_id);

    // Matches ykcs11_tests.c's test_token_info(): no session is opened
    // before calling C_GetTokenInfo, so ulSessionCount/ulRwSessionCount
    // below are expected to be exactly 0.
    let info = token_info(slot_id);

    assert_prefix(&info.label, b"YubiKey PIV", "CK_TOKEN_INFO.label");
    assert_prefix(&info.model, b"YubiKey", "CK_TOKEN_INFO.model");

    // Matches ykcs11_tests.c's test_token_info(): CKF_RNG|CKF_LOGIN_REQUIRED
    // |CKF_USER_PIN_INITIALIZED|CKF_TOKEN_INITIALIZED, with no extra
    // retry-related flags since `token_init` just reset the PIN to full
    // retries (see `PivBackend::token_info`'s `extra_flags` doc comment).
    let expected_flags = (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
        as CK_FLAGS;
    assert_eq!(info.flags, expected_flags, "CK_TOKEN_INFO.flags");

    assert_eq!(info.ulMaxSessionCount, 16, "ulMaxSessionCount");
    assert_eq!(info.ulSessionCount, 0, "ulSessionCount");
    assert_eq!(info.ulMaxRwSessionCount, 16, "ulMaxRwSessionCount");
    assert_eq!(info.ulRwSessionCount, 0, "ulRwSessionCount");

    assert_eq!(info.ulMinPinLen, 6, "ulMinPinLen");
    assert_eq!(info.ulMaxPinLen, 64, "ulMaxPinLen");

    let unavailable = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
    assert_eq!(info.ulTotalPublicMemory, unavailable, "ulTotalPublicMemory");
    assert_eq!(info.ulFreePublicMemory, unavailable, "ulFreePublicMemory");
    assert_eq!(info.ulTotalPrivateMemory, unavailable, "ulTotalPrivateMemory");
    assert_eq!(info.ulFreePrivateMemory, unavailable, "ulFreePrivateMemory");

    assert_eq!(info.hardwareVersion.major, 1, "hardwareVersion.major");
    assert_eq!(info.hardwareVersion.minor, 0, "hardwareVersion.minor");

    assert_eq!(info.utcTime, [b' '; 16], "CK_TOKEN_INFO.utcTime");

    eprintln!(
        "detected firmware {}.{}",
        info.firmwareVersion.major, info.firmwareVersion.minor
    );

    let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
    assert_ok(rv, "C_Finalize");
}
