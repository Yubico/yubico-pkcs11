/*
 * Copyright (c) 2026 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//! Hardware-gated integration tests for the YubiKey PIV PKCS#11 module —
//! the Rust equivalent of yubico-piv-tool's `ykcs11/tests/ykcs11_tests.c`
//! (that harness has no single `token_init()` either; `reset.sh` blocks the
//! PIN/PUK and calls the CLI's `-areset` before the test binary runs). This
//! module plays the same role for `ykcs11`, calling the real C ABI
//! (`pub use dispatch::*` at the crate root) exactly as `pkcs11-tool` or any
//! other PKCS#11 consumer would — no internal shortcuts.
//!
//! Covers importing ML-DSA and ML-KEM private keys (`C_CreateObject`) and
//! ML-KEM encapsulate/decapsulate (`C_EncapsulateKey`/`C_DecapsulateKey`,
//! reached via `C_GetInterfaceList`/`C_GetInterface` -- see
//! `dispatch.rs`'s own doc comment on `G_INTERFACES` for why those aren't
//! reachable through `C_GetFunctionList`); more will be added later
//! (generation, signing, etc.).
//!
//! # Running
//!
//! These tests require a real YubiKey plugged in and are destructive (they
//! wipe the PIV application). They do **nothing** — no PC/SC access at all —
//! unless explicitly opted into:
//!
//! ```sh
//! YKCS11_HW_TESTS=1 cargo test -p ykcs11 --test hardware_tests
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

/// Factory-default PIV user PIN -- what `token_init`'s underlying
/// `ActivePivSession::reset()` leaves the PIN at after a reset. Private-key
/// crypto operations (sign/decrypt/derive/decapsulate) go through the
/// device's AUTHENTICATE APDU, which is gated on this PIN being verified
/// (`CKU_USER`), entirely independent of the `CKU_SO` management-key
/// authentication `open_so_session` performs -- the management key only
/// authorizes administrative operations like key generation/import. Without
/// a `CKU_USER` login first, the device responds SW=0x6982 (security status
/// not satisfied), which this module's `piv_error_to_rv` surfaces as
/// `CKR_DEVICE_ERROR`.
const DEFAULT_USER_PIN: &[u8] = b"123456";

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

/// Logs out of whatever role `h_session` currently holds (expected to be
/// `CKU_SO`, from `open_so_session`) and logs back in as `CKU_USER` with the
/// factory-default PIN -- the login state is mutually exclusive between the
/// two roles on a given slot (`PivBackend::login`), so this can't just be
/// layered on top of the existing SO session.
fn switch_to_user_login(h_session: CK_SESSION_HANDLE) {
    let rv = unsafe { ykcs11::C_Logout(h_session) };
    assert_ok(rv, "C_Logout(CKU_SO)");

    let rv = unsafe {
        ykcs11::C_Login(
            h_session,
            CKU_USER as CK_USER_TYPE,
            DEFAULT_USER_PIN.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_USER_PIN.len() as CK_ULONG,
        )
    };
    assert_ok(rv, "C_Login(CKU_USER)");
}

fn close_session(h_session: CK_SESSION_HANDLE) {
    let rv = unsafe { ykcs11::C_Logout(h_session) };
    assert_ok(rv, "C_Logout");
    let rv = unsafe { ykcs11::C_CloseSession(h_session) };
    assert_ok(rv, "C_CloseSession");
}

/// Reads a single fixed-length attribute via `C_GetAttributeValue`.
/// `C_GetAttributeValue` writes the result directly into the buffer backing
/// `attr(...)`'s `pValue` (`backend.rs`'s `copy_nonoverlapping` into the
/// caller's own allocation), so the returned `Vec` already reflects the
/// answer -- no separate read-back step needed. Callers must already know
/// the exact expected length (every attribute used in this file does: fixed
/// by the PKCS#11 `CK_ULONG` width, or by FIPS 203/204's own fixed sizes
/// per parameter set).
fn get_attribute(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    attr_type: u32,
    len: usize,
    what: &str,
) -> Vec<u8> {
    let buf = vec![0u8; len];
    let mut template = [attr(attr_type, &buf)];
    let rv = unsafe {
        ykcs11::C_GetAttributeValue(
            h_session,
            h_object,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        )
    };
    assert_ok(rv, &format!("C_GetAttributeValue ({what})"));
    buf
}

/// Finds the one object matching `class`/`id` via
/// `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` -- e.g. the
/// `CKO_PUBLIC_KEY` object a `C_CreateObject`/`C_GenerateKeyPair` call also
/// populates alongside the private key it was actually asked for, at the
/// same `CKA_ID` but a different (and otherwise unpredictable from the
/// caller's side) handle.
fn find_object_handle(h_session: CK_SESSION_HANDLE, class: u32, id: u8, what: &str) -> CK_OBJECT_HANDLE {
    let class_bytes = ulong_bytes(class);
    let id_bytes = [id];
    let mut template = [attr(CKA_CLASS, &class_bytes), attr(CKA_ID, &id_bytes)];
    let rv = unsafe {
        ykcs11::C_FindObjectsInit(h_session, template.as_mut_ptr(), template.len() as CK_ULONG)
    };
    assert_ok(rv, &format!("C_FindObjectsInit ({what})"));

    let mut handles = [0 as CK_OBJECT_HANDLE; 1];
    let mut count: CK_ULONG = 0;
    let rv = unsafe {
        ykcs11::C_FindObjects(h_session, handles.as_mut_ptr(), handles.len() as CK_ULONG, &mut count)
    };
    assert_ok(rv, &format!("C_FindObjects ({what})"));
    assert_eq!(count, 1, "{what}: expected exactly one matching object, found {count}");

    let rv = unsafe { ykcs11::C_FindObjectsFinal(h_session) };
    assert_ok(rv, &format!("C_FindObjectsFinal ({what})"));

    handles[0]
}

/// A `CK_MECHANISM` with no parameter -- every mechanism this file uses
/// (`CKM_ML_KEM`) takes none. Named `no_param_mechanism` rather than
/// `mechanism` so call sites can freely use `mechanism` as a local variable
/// name for the result without shadowing this function.
fn no_param_mechanism(ty: u32) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: ty as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    }
}

/// Calls `C_GetInterface("PKCS 11", NULL, ...)` and returns the full 3.2
/// function table it points at. `C_EncapsulateKey`/`C_DecapsulateKey` are
/// only reachable this way -- they aren't part of the legacy
/// `CK_FUNCTION_LIST` `C_GetFunctionList` returns (see this file's module
/// doc comment, and `dispatch.rs`'s own doc comment on `G_INTERFACES`) --
/// so this exercises the actual interface-discovery mechanism those two
/// functions need, rather than calling `ykcs11::C_EncapsulateKey` directly
/// the way every other function in this file reaches `ykcs11`'s C ABI.
fn get_3_2_function_list() -> &'static CK_FUNCTION_LIST_3_2 {
    const INTERFACE_NAME: &[u8] = b"PKCS 11\0";
    let mut p_interface: CK_INTERFACE_PTR = ptr::null_mut();
    let rv = unsafe {
        ykcs11::C_GetInterface(
            INTERFACE_NAME.as_ptr() as CK_UTF8CHAR_PTR,
            ptr::null_mut(),
            &mut p_interface,
            0,
        )
    };
    assert_ok(rv, "C_GetInterface");
    assert!(!p_interface.is_null(), "C_GetInterface returned a null interface");

    let function_list = unsafe { (*p_interface).pFunctionList as *const CK_FUNCTION_LIST_3_2 };
    assert!(!function_list.is_null(), "C_GetInterface returned a null function list");
    unsafe { &*function_list }
}

/// Imports a private key via `C_CreateObject`, confirms the slot reports
/// the expected `CKA_KEY_TYPE` back afterward (not just that the call
/// returned `CKR_OK`, but that the import actually stuck on the device),
/// and returns the new private-key object's handle.
fn import_and_verify(
    h_session: CK_SESSION_HANDLE,
    id: u8,
    key_type: u32,
    parameter_set: u32,
    seed: &[u8],
    what: &str,
) -> CK_OBJECT_HANDLE {
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

    let got_key_type = get_attribute(h_session, h_object, CKA_KEY_TYPE, key_type_bytes.len(), what);
    assert_eq!(
        got_key_type, key_type_bytes,
        "{what}: CKA_KEY_TYPE readback mismatch after import"
    );

    h_object
}

#[test]
fn hardware_ml_dsa_and_ml_kem_keys() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_ml_dsa_and_ml_kem_keys: set {RUN_ENV_VAR}=1 to run \
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
    // authentication used above for the imports. See `DEFAULT_USER_PIN`'s
    // own doc comment.
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
    // in advance, so (like the rest of this file) there's no need for the
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
