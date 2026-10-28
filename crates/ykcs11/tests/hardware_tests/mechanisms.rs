// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_GetMechanismList`/`C_GetMechanismInfo` hardware coverage -- the Rust
//! equivalent of `ykcs11_tests.c`'s `test_mechanism_list_and_info()`.

use crate::common::*;
use pkcs11_sys::*;
use std::ptr;

/// The expected mechanism list/info table -- the Rust equivalent of
/// `ykcs11_tests.c`'s `token_mechanisms[]`/`token_mechanism_infos[]`/
/// `token_mechanism_infos_3[]`, collapsed into one table parameterized on
/// `rsa_max` instead of two static tables keyed on a `main()`-level
/// `ed25519_supported` global (see `firmware_at_least`'s doc comment on why
/// these tests avoid that pattern). Order here is cosmetic -- the test below
/// compares this against `C_GetMechanismList`'s output as a set, not
/// position-by-position like the C reference's `memcmp` -- unlike
/// `ykcs11_tests.c`'s `token_mechanisms[]`, the PKCS#11 spec makes no
/// guarantee about `C_GetMechanismList`'s ordering. Also includes 4 PQC
/// mechanisms (`CKM_ML_DSA_KEY_PAIR_GEN`/`CKM_ML_KEM_KEY_PAIR_GEN`/
/// `CKM_ML_KEM`/`CKM_ML_DSA`) that have no equivalent in `ykcs11_tests.c`'s
/// `token_mechanisms[]` at all -- new additions with no C-side expectation.
/// Must stay in sync with `mechanism_table()` in `src/mechanisms.rs`.
fn expected_mechanisms(rsa_max: CK_ULONG) -> Vec<(CK_MECHANISM_TYPE, CK_ULONG, CK_ULONG, CK_FLAGS)> {
    let rsa_sign_verify = (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS;
    let ec_sign_verify =
        (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS;
    let ec_keygen =
        (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS;

    vec![
        (CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 1024, rsa_max, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS),
        (
            CKM_RSA_PKCS as CK_MECHANISM_TYPE,
            1024,
            rsa_max,
            (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        ),
        (CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE, 1024, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS),
        (
            CKM_RSA_X_509 as CK_MECHANISM_TYPE,
            1024,
            rsa_max,
            (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS,
        ),
        (CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE, 1024, rsa_max, rsa_sign_verify),
        (CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 256, 384, ec_keygen),
        (CKM_ECDSA as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE, 256, 384, ec_sign_verify),
        (
            CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
            256,
            384,
            (CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS,
        ),
        (CKM_SHA_1 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA256 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA384 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA512 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 255, 255, ec_keygen),
        (CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 255, 255, ec_keygen),
        (CKM_EDDSA as CK_MECHANISM_TYPE, 255, 255, ec_sign_verify),
        // PQC additions -- no C reference entry to match (see mechanisms.rs).
        (CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS),
        (CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS),
        (CKM_ML_KEM as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_ENCAPSULATE | CKF_DECAPSULATE) as CK_FLAGS),
        (CKM_ML_DSA as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
    ]
}

/// The Rust equivalent of `ykcs11_tests.c`'s `test_mechanism_list_and_info()`.
/// Unlike the other hardware tests in this crate, this one doesn't call
/// `token_init` -- the C reference doesn't reset the device for this test
/// either, since mechanism list/info is independent of PIV application
/// state. See `expected_mechanisms`'s own doc comment for how this departs
/// from the C reference's two-static-tables-plus-global approach.
#[test]
fn hardware_mechanism_list_and_info() {
    if !hardware_tests_enabled() {
        eprintln!("skipping hardware_mechanism_list_and_info: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
    assert_ok(rv, "C_Initialize");

    let slot_id = first_token_present_slot();

    // Matches ykcs11_tests.c's ed25519_supported gate (firmware >= 5.7):
    // RSA key sizes above 2048 bits need firmware 5.7+ (backend.rs's own
    // mechanism_info()).
    let info = token_info(slot_id);
    let rsa_max: CK_ULONG = if firmware_at_least(&info, 5, 7) { 4096 } else { 2048 };
    let expected = expected_mechanisms(rsa_max);

    let mut count: CK_ULONG = 0;
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, ptr::null_mut(), &mut count) };
    assert_ok(rv, "C_GetMechanismList (count)");
    assert_eq!(count as usize, expected.len(), "unexpected mechanism count");

    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, mechs.as_mut_ptr(), &mut count) };
    assert_ok(rv, "C_GetMechanismList (fill)");

    // Order isn't part of the PKCS#11 contract for C_GetMechanismList --
    // unlike ykcs11_tests.c's memcmp (which only works because it controls
    // the array layout on both sides), compare as sets.
    let mut mechs_sorted = mechs.clone();
    mechs_sorted.sort();
    let mut expected_types: Vec<CK_MECHANISM_TYPE> = expected.iter().map(|e| e.0).collect();
    expected_types.sort();
    assert_eq!(mechs_sorted, expected_types, "mechanism set mismatch");

    for (mechanism, min, max, flags) in expected {
        let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { ykcs11::C_GetMechanismInfo(slot_id, mechanism, &mut mech_info) };
        assert_ok(rv, &format!("C_GetMechanismInfo(0x{mechanism:x})"));
        assert_eq!(mech_info.ulMinKeySize, min, "0x{mechanism:x}: ulMinKeySize");
        assert_eq!(mech_info.ulMaxKeySize, max, "0x{mechanism:x}: ulMaxKeySize");
        assert_eq!(mech_info.flags, flags, "0x{mechanism:x}: flags");
    }

    let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
    assert_ok(rv, "C_Finalize");
}
