// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! ML-KEM private-key import (`C_CreateObject`) and encapsulate/decapsulate
//! (`C_EncapsulateKey`/`C_DecapsulateKey`, reached via
//! `C_GetInterfaceList`/`C_GetInterface` -- see `dispatch.rs`'s own doc
//! comment on `G_INTERFACES` for why those aren't reachable through
//! `C_GetFunctionList`) hardware coverage.

use crate::common::*;
use pkcs11_sys::*;
use std::ptr;

#[test]
fn hardware_ml_kem_keys() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_ml_kem_keys: set {RUN_ENV_VAR}=1 to run \
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
            "skipping hardware_ml_kem_keys: firmware {}.{} is older than the \
             6.0 ML-DSA/ML-KEM require",
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
    let h_ml_kem_priv = import_and_verify(
        h_session,
        3, // Key Management (9d) -- the traditional slot for key-agreement keys
        CKK_ML_KEM,
        CKP_ML_KEM_512,
        &[0x24u8; 64],
        "ML-KEM-512",
    );

    // Decapsulate is a private-key crypto op (AUTHENTICATE APDU), gated on
    // CKU_USER PIN verification -- distinct from the CKU_SO management-key
    // authentication used above for the import. See `DEFAULT_USER_PIN`'s own
    // doc comment.
    switch_to_user_login(h_session);

    encapsulate_and_decapsulate_round_trip(h_session, h_ml_kem_priv);

    close_session(h_session);

    let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
    assert_ok(rv, "C_Finalize");
}

/// Encapsulates a fresh shared secret against the ML-KEM-512 public key
/// `import_and_verify` also populated (same `CKA_ID` as `h_private_key`,
/// discovered via `C_FindObjects`), decapsulates the resulting ciphertext
/// with `h_private_key`, and confirms both sides land on the identical
/// shared secret -- the actual correctness property that matters, not just
/// "both calls returned CKR_OK".
fn encapsulate_and_decapsulate_round_trip(h_session: CK_SESSION_HANDLE, h_private_key: CK_OBJECT_HANDLE) {
    let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, 3, "ML-KEM-512 public key");

    let function_list = get_3_2_function_list();
    let c_encapsulate_key = function_list
        .C_EncapsulateKey
        .expect("C_EncapsulateKey not wired into the 3.2 interface");
    let c_decapsulate_key = function_list
        .C_DecapsulateKey
        .expect("C_DecapsulateKey not wired into the 3.2 interface");

    // FIPS 203's fixed ML-KEM-512 ciphertext/shared-secret lengths -- known
    // in advance, so (like the rest of these tests) there's no need for the
    // two-call buffer-size dance C_EncapsulateKey otherwise supports.
    let mut encap_mechanism = no_param_mechanism(CKM_ML_KEM);
    let mut ciphertext = vec![0u8; 768];
    let mut ciphertext_len = ciphertext.len() as CK_ULONG;
    let mut h_encap_secret: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        c_encapsulate_key(
            h_session,
            &mut encap_mechanism,
            h_public_key,
            ptr::null_mut(),
            0,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            &mut h_encap_secret,
        )
    };
    assert_ok(rv, "C_EncapsulateKey");
    assert_eq!(
        ciphertext_len as usize,
        ciphertext.len(),
        "unexpected ML-KEM-512 ciphertext length"
    );
    assert_ne!(h_encap_secret, 0, "C_EncapsulateKey returned a null handle");

    let encapsulated_secret = get_attribute(h_session, h_encap_secret, CKA_VALUE, 32, "encapsulated secret");

    let mut decap_mechanism = no_param_mechanism(CKM_ML_KEM);
    let mut h_decap_secret: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        c_decapsulate_key(
            h_session,
            &mut decap_mechanism,
            h_private_key,
            ptr::null_mut(),
            0,
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            &mut h_decap_secret,
        )
    };
    assert_ok(rv, "C_DecapsulateKey");
    assert_ne!(h_decap_secret, 0, "C_DecapsulateKey returned a null handle");

    let decapsulated_secret = get_attribute(h_session, h_decap_secret, CKA_VALUE, 32, "decapsulated secret");

    assert_eq!(
        encapsulated_secret, decapsulated_secret,
        "host-encapsulated and device-decapsulated shared secrets don't match"
    );
}
