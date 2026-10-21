// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! Hardware-gated integration tests for the YubiKey PIV PKCS#11 module —
//! the Rust equivalent of yubico-piv-tool's `ykcs11/tests/ykcs11_tests.c`
//! (that harness has no single `token_init()` either; `reset.sh` blocks the
//! PIN/PUK and calls the CLI's `-areset` before the test binary runs). This
//! module plays the same role for `ykcs11`, calling the real C ABI
//! (`pub use dispatch::*` at the crate root) exactly as `pkcs11-tool` or any
//! other PKCS#11 consumer would — no internal shortcuts.
//!
//! For now this only covers importing ML-DSA and ML-KEM private keys
//! (`C_CreateObject`); more will be added later (generation, signing,
//! decapsulation, etc.).
//!
//! # Running
//!
//! These tests require a real YubiKey plugged in and are destructive (they
//! wipe the PIV application). They do **nothing** — no PC/SC access at all —
//! unless explicitly opted into:
//!
//! ```sh
//! YKCS11_HW_TESTS=1 cargo test -p ykcs11 --test hardware_import_tests
//! ```
//!
//! # !!! WARNING !!!
//!
//! Running with `YKCS11_HW_TESTS=1` resets the PIV application on every
//! YubiKey `C_GetSlotList` reports as present (via `C_InitToken`, the real
//! "wipe and reinitialize" PKCS#11 call) — every PIV key and certificate on
//! it is permanently destroyed. Only ever run this against a dedicated
//! test/development YubiKey, never one holding keys you care about.
//!
//! Only one hardware test exists right now, so there's no cross-test
//! parallelism concern yet — but `cargo test` runs tests in a binary
//! concurrently by default, and two tests racing to reset/open a session on
//! the same physical device will not behave sanely. Whoever adds the next
//! hardware test here should either serialize access through a shared
//! `Mutex`/`OnceLock`, or document running this binary with
//! `--test-threads=1`.

use pkcs11_sys::*;
use std::ptr;

const RUN_ENV_VAR: &str = "YKCS11_HW_TESTS";

/// Hex-encoded factory-default PIV management key (yubikit's
/// `DEFAULT_MANAGEMENT_KEY`: the classic 24-byte `01 02 03 04 05 06 07 08`
/// pattern, repeated three times). This module's `C_InitToken`/`C_Login`
/// both take the management key as this literal hex ASCII string — the
/// same value every `pkcs11-tool --so-pin 010203...` invocation in this
/// project's manual testing has used.
const DEFAULT_MGMT_KEY_HEX: &[u8] = b"010203040506070801020304050607080102030405060708";

fn hardware_tests_enabled() -> bool {
    std::env::var(RUN_ENV_VAR).as_deref() == Ok("1")
}

fn assert_ok(rv: CK_RV, what: &str) {
    assert_eq!(rv, CKR_OK as CK_RV, "{what} failed: rv={rv:#x}");
}

fn ulong_bytes(v: u32) -> Vec<u8> {
    (v as CK_ULONG).to_ne_bytes().to_vec()
}

fn attr(ty: u32, value: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: ty as CK_ATTRIBUTE_TYPE,
        pValue: value.as_ptr() as CK_VOID_PTR,
        ulValueLen: value.len() as CK_ULONG,
    }
}

/// Every `CK_*` slot/session/login call below is the literal public C ABI
/// (`pub use dispatch::*`), called in-process rather than through `dlopen` —
/// this crate's `crate-type` includes `"rlib"` specifically so integration
/// tests can do this; see Cargo.toml's own comment on that line.
fn first_token_present_slot() -> CK_SLOT_ID {
    let mut count: CK_ULONG = 0;
    let rv = unsafe { ykcs11::C_GetSlotList(CK_TRUE as CK_BBOOL, ptr::null_mut(), &mut count) };
    assert_ok(rv, "C_GetSlotList (count)");
    assert!(
        count > 0,
        "no YubiKey detected -- plug one in before running with {RUN_ENV_VAR}=1"
    );

    let mut slots = vec![0 as CK_SLOT_ID; count as usize];
    let rv =
        unsafe { ykcs11::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count) };
    assert_ok(rv, "C_GetSlotList (fill)");
    slots[0]
}

/// Resets the PIV application to factory defaults via the real
/// `C_InitToken` PKCS#11 call -- this module's actual "reset the token"
/// entry point (see `init_token.rs`'s own doc comment: it blocks the
/// PIN/PUK, resets, then restores the management key it was given, which
/// here is the factory default, leaving the device in a known, fully-wiped
/// state every run starts from).
fn token_init(slot_id: CK_SLOT_ID) {
    eprintln!(
        "\n\
         ********************************************************************\n\
         *** WARNING: resetting the PIV application on YubiKey slot {slot_id}.\n\
         *** ALL PIV KEYS AND CERTIFICATES ON THIS DEVICE WILL BE ERASED.\n\
         *** Only run these tests against a dedicated test/development key.\n\
         ********************************************************************\n"
    );

    let rv = unsafe {
        ykcs11::C_InitToken(
            slot_id,
            DEFAULT_MGMT_KEY_HEX.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_MGMT_KEY_HEX.len() as CK_ULONG,
            ptr::null_mut(),
        )
    };
    assert_ok(rv, "C_InitToken");
}

fn open_so_session(slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut h_session: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_OpenSession(
            slot_id,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ptr::null_mut(),
            None,
            &mut h_session,
        )
    };
    assert_ok(rv, "C_OpenSession");

    let rv = unsafe {
        ykcs11::C_Login(
            h_session,
            CKU_SO as CK_USER_TYPE,
            DEFAULT_MGMT_KEY_HEX.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_MGMT_KEY_HEX.len() as CK_ULONG,
        )
    };
    assert_ok(rv, "C_Login(CKU_SO)");

    h_session
}

fn close_session(h_session: CK_SESSION_HANDLE) {
    let rv = unsafe { ykcs11::C_Logout(h_session) };
    assert_ok(rv, "C_Logout");
    let rv = unsafe { ykcs11::C_CloseSession(h_session) };
    assert_ok(rv, "C_CloseSession");
}

/// Imports a private key via `C_CreateObject` and confirms the slot reports
/// the expected `CKA_KEY_TYPE` back afterward -- not just that the call
/// returned `CKR_OK`, but that the import actually stuck on the device.
fn import_and_verify(
    h_session: CK_SESSION_HANDLE,
    id: u8,
    key_type: u32,
    parameter_set: u32,
    seed: &[u8],
    what: &str,
) {
    let class = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type_bytes = ulong_bytes(key_type);
    let id_bytes = [id];
    let param_set_bytes = ulong_bytes(parameter_set);

    let mut template = [
        attr(CKA_CLASS, &class),
        attr(CKA_KEY_TYPE, &key_type_bytes),
        attr(CKA_ID, &id_bytes),
        attr(CKA_PARAMETER_SET, &param_set_bytes),
        attr(CKA_SEED, seed),
    ];

    let mut h_object: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_CreateObject(
            h_session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut h_object,
        )
    };
    assert_ok(rv, &format!("C_CreateObject ({what})"));
    assert_ne!(h_object, 0, "{what}: C_CreateObject returned a null handle");

    // `C_GetAttributeValue` writes the result directly into this buffer via
    // `pValue` (`backend.rs`'s `copy_nonoverlapping` into the caller's own
    // allocation), so `got_key_type` itself reflects the answer afterward --
    // no separate read-back step needed.
    let got_key_type = vec![0u8; key_type_bytes.len()];
    let mut verify_template = [attr(CKA_KEY_TYPE, &got_key_type)];
    let rv = unsafe {
        ykcs11::C_GetAttributeValue(
            h_session,
            h_object,
            verify_template.as_mut_ptr(),
            verify_template.len() as CK_ULONG,
        )
    };
    assert_ok(rv, &format!("C_GetAttributeValue ({what})"));
    assert_eq!(
        got_key_type, key_type_bytes,
        "{what}: CKA_KEY_TYPE readback mismatch after import"
    );
}

#[test]
fn hardware_import_ml_dsa_and_ml_kem_keys() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_import_ml_dsa_and_ml_kem_keys: set {RUN_ENV_VAR}=1 to run \
             (destructive -- see this file's module doc comment)"
        );
        return;
    }

    let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
    assert_ok(rv, "C_Initialize");

    let slot_id = first_token_present_slot();
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
    import_and_verify(
        h_session,
        3, // Key Management (9d) -- the traditional slot for key-agreement keys
        CKK_ML_KEM,
        CKP_ML_KEM_512,
        &[0x24u8; 64],
        "ML-KEM-512",
    );

    close_session(h_session);

    let rv = unsafe { ykcs11::C_Finalize(ptr::null_mut()) };
    assert_ok(rv, "C_Finalize");
}
