// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! ML-DSA private-key import hardware coverage (`C_CreateObject`).

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

#[test]
fn hardware_ml_dsa() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_ml_dsa: set {RUN_ENV_VAR}=1 to run \
             (destructive -- see this crate's module doc comment)"
        );
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
    assert_ok(rv, "C_Initialize");

    let slot_id = first_token_present_slot();

    // ML-DSA/ML-KEM need firmware >= 6.0 -- check before `token_init`'s
    // destructive reset so an older device isn't wiped for nothing.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 6, 0) {
        eprintln!(
            "skipping hardware_ml_dsa: firmware {}.{} is older than the 6.0 \
             ML-DSA/ML-KEM require",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
        assert_ok(rv, "C_Finalize");
        return;
    }

    token_init(slot_id);

    let h_session = open_so_session(slot_id);

    // Hardcoded, arbitrary seed material -- FIPS 204/203 don't require
    // anything special of the seed itself, any correctly-sized byte string
    // is a valid key seed, so there's no need to generate real randomness
    // for an import test.
    import_and_verify(
        h_session,
        1, // Authentication (9a)
        CKK_ML_DSA,
        CKP_ML_DSA_44,
        &[0x42u8; 32],
        "ML-DSA-44",
    );

    close_session(h_session);

    let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
    assert_ok(rv, "C_Finalize");
}
