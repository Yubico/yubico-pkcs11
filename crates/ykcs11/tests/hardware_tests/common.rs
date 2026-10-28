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

//! Shared connection/session/object plumbing for every hardware test module
//! under `tests/hardware_tests/` -- factored out here so each test file only
//! contains the logic specific to what it's actually testing. See `crate`'s
//! own module doc comment (`tests/hardware_tests.rs`) for the overall
//! running/safety story.

use pkcs11_sys::*;
use std::ptr;
use std::sync::Mutex;

/// Held for the duration of every `#[test]` fn across every module in this
/// test binary -- see `crate`'s own module doc comment for why.
pub(crate) static HARDWARE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) const RUN_ENV_VAR: &str = "YKCS11_HW_TESTS";

/// Hex-encoded factory-default PIV management key (yubikit's
/// `DEFAULT_MANAGEMENT_KEY`: the classic 24-byte `01 02 03 04 05 06 07 08`
/// pattern, repeated three times). This module's `C_InitToken`/`C_Login`
/// both take the management key as this literal hex ASCII string — the
/// same value every `pkcs11-tool --so-pin 010203...` invocation in this
/// project's manual testing has used.
pub(crate) const DEFAULT_MGMT_KEY_HEX: &[u8] = b"010203040506070801020304050607080102030405060708";

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
pub(crate) const DEFAULT_USER_PIN: &[u8] = b"123456";

pub(crate) fn hardware_tests_enabled() -> bool {
    std::env::var(RUN_ENV_VAR).as_deref() == Ok("1")
}

pub(crate) fn assert_ok(rv: CK_RV, what: &str) {
    assert_eq!(rv, CKR_OK as CK_RV, "{what} failed: rv={rv:#x}");
}

/// Asserts `field` (a fixed-size `CK_CHAR` array, e.g. `CK_TOKEN_INFO.label`)
/// starts with `expected` -- the Rust equivalent of ykcs11_tests.c's
/// `strncmp(info.field, EXPECTED, strlen(EXPECTED))` prefix checks.
pub(crate) fn assert_prefix(field: &[CK_CHAR], expected: &[u8], what: &str) {
    assert!(
        field.len() >= expected.len(),
        "{what}: field shorter than expected prefix"
    );
    assert_eq!(
        &field[..expected.len()],
        expected,
        "{what}: expected prefix {:?}, got {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(&field[..expected.len()])
    );
}

/// Reads `CK_TOKEN_INFO` for `slot_id`. Tests that need to gate behavior on
/// device capability (e.g. firmware version) call this directly rather than
/// relying on a flag set by another test via shared state -- each test is
/// independent and queries the device fresh, unlike `ykcs11_tests.c`'s
/// `main()`-level globals (`is_neo`, `ed25519_supported`) set by
/// `test_token_info()` and read by later tests in the same run.
pub(crate) fn token_info(slot_id: CK_SLOT_ID) -> CK_TOKEN_INFO {
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = unsafe { ykcs11::C_GetTokenInfo(slot_id, &mut info) };
    assert_ok(rv, "C_GetTokenInfo");
    info
}

/// Whether `info`'s firmware version is at least `major.minor` -- e.g.
/// ML-DSA/ML-KEM require firmware >= 6.0. `CK_TOKEN_INFO.firmwareVersion`
/// (`CK_VERSION`) has only major/minor fields, no patch component, so this
/// is the finest granularity the public PKCS#11 API exposes; every feature
/// gate these tests need only ever cares about the major version anyway.
/// Different firmware ranges gate different things (PIV slot count,
/// available mechanisms, key types, touch/PIN policies, ...) -- there's no
/// single boolean (like `ykcs11_tests.c`'s `is_neo`) that captures all of
/// that, so each affected test should call this with whatever threshold
/// its own feature actually needs, rather than reasoning from a device
/// "model"/"generation" label.
pub(crate) fn firmware_at_least(info: &CK_TOKEN_INFO, major: u8, minor: u8) -> bool {
    (info.firmwareVersion.major, info.firmwareVersion.minor) >= (major, minor)
}

pub(crate) fn ulong_bytes(v: u32) -> Vec<u8> {
    (v as CK_ULONG).to_ne_bytes().to_vec()
}

pub(crate) fn attr(ty: u32, value: &[u8]) -> CK_ATTRIBUTE {
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
pub(crate) fn first_token_present_slot() -> CK_SLOT_ID {
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
pub(crate) fn token_init(slot_id: CK_SLOT_ID) {
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

pub(crate) fn open_so_session(slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
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
pub(crate) fn switch_to_user_login(h_session: CK_SESSION_HANDLE) {
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

pub(crate) fn close_session(h_session: CK_SESSION_HANDLE) {
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
/// the exact expected length (every attribute used by these tests does:
/// fixed by the PKCS#11 `CK_ULONG` width, or by FIPS 203/204's own fixed
/// sizes per parameter set).
pub(crate) fn get_attribute(
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
pub(crate) fn find_object_handle(h_session: CK_SESSION_HANDLE, class: u32, id: u8, what: &str) -> CK_OBJECT_HANDLE {
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

/// A `CK_MECHANISM` with no parameter -- every mechanism these tests use
/// (`CKM_ML_KEM`) takes none. Named `no_param_mechanism` rather than
/// `mechanism` so call sites can freely use `mechanism` as a local variable
/// name for the result without shadowing this function.
pub(crate) fn no_param_mechanism(ty: u32) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: ty as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    }
}

/// Calls `C_GetInterface("PKCS 11", NULL, ...)` and returns the full 3.2
/// function table it points at. `C_EncapsulateKey`/`C_DecapsulateKey` are
/// only reachable this way -- they aren't part of the legacy
/// `CK_FUNCTION_LIST` `C_GetFunctionList` returns (see `crate`'s own module
/// doc comment, and `dispatch.rs`'s own doc comment on `G_INTERFACES`) --
/// so this exercises the actual interface-discovery mechanism those two
/// functions need, rather than calling `ykcs11::C_EncapsulateKey` directly
/// the way every other function here reaches `ykcs11`'s C ABI.
pub(crate) fn get_3_2_function_list() -> &'static CK_FUNCTION_LIST_3_2 {
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
pub(crate) fn import_and_verify(
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
