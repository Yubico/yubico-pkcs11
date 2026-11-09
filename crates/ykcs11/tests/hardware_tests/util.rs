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
//! under `tests/hardware_tests/`

use pkcs11_sys::*;
use std::ptr;
use std::sync::{Mutex, Once};

/// Held for the duration of every `#[test]` to ensure single threadedness
pub(crate) static HARDWARE_LOCK: Mutex<()> = Mutex::new(());

static INIT: Once = Once::new();

pub(crate) const RUN_ENV_VAR: &str = "YKCS11_HW_TESTS";

pub(crate) const DEFAULT_USER_PIN: &[u8] = b"123456";
pub(crate) const DEFAULT_MGMT_KEY_HEX: &[u8] = b"010203040506070801020304050607080102030405060708";

pub(crate) const P256_EC_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub(crate) const P384_EC_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

pub(crate) const SLOT_LIST_EXTENDED: &[u8] = &[1, 2, 4, 5, 24];
pub(crate) const SLOT_LIST: &[u8] = &[1, 2, 4];

pub(crate) fn hardware_tests_enabled() -> bool {
    std::env::var(RUN_ENV_VAR).as_deref() == Ok("1")
}

/// Calls `C_Initialize` exactly once for this test binary's whole process,
/// no matter how many `#[test]` fns call this. The live PC/SC connection
/// and PIV session inside `ykcs11`'s own process-wide state then survive
/// across every test (nothing calls `C_Finalize` anymore), so only the
/// first test to actually need a connection pays for it. `HARDWARE_LOCK` is
/// already held by the caller before this runs, so whichever test gets
/// there first performs the real call and every other test's call is a
/// no-op.
pub(crate) fn ensure_initialized() {
    INIT.call_once(|| {
        let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");
    });
}

// pub(crate) fn assert_ok(rv: CK_RV, what: &str) {
//     assert_eq!(rv, CKR_OK as CK_RV, "{what} failed: rv={rv:#x}");
// }

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

pub(crate) fn token_info(slot_id: CK_SLOT_ID) -> CK_TOKEN_INFO {
    let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
    let rv = unsafe { ykcs11::C_GetTokenInfo(slot_id, &mut info) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetTokenInfo");
    info
}

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

pub(crate) fn first_populated_slot() -> CK_SLOT_ID {
    let mut count: CK_ULONG = 0;
    let rv = unsafe { ykcs11::C_GetSlotList(CK_TRUE as CK_BBOOL, ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList (count)");
    assert!(
        count > 0,
        "no YubiKey detected -- plug one in before running with {RUN_ENV_VAR}=1"
    );

    let mut slots = vec![0 as CK_SLOT_ID; count as usize];
    let rv =
        unsafe { ykcs11::C_GetSlotList(CK_TRUE as CK_BBOOL, slots.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSlotList (fill)");
    slots[0]
}

/// Resets the PIV application to factory defaults via the real
/// `C_InitToken` PKCS#11 call
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
    assert_eq!(rv, CKR_OK as CK_RV, "C_InitToken");
}

pub(crate) fn open_session(slot_id: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_OpenSession(
            slot_id,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ptr::null_mut(),
            None,
            &mut session,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

    session
}

pub(crate) fn login_user(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let rv = unsafe {
        ykcs11::C_Login(
            session,
            CKU_USER as CK_USER_TYPE,
            DEFAULT_USER_PIN.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_USER_PIN.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, expected, "C_Login(CKU_USER). Expected {expected:#x}. Found {rv:#x}");
}

pub(crate) fn login_so(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let rv = unsafe {
        ykcs11::C_Login(
            session,
            CKU_SO as CK_USER_TYPE,
            DEFAULT_MGMT_KEY_HEX.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_MGMT_KEY_HEX.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, expected, "C_Login(CKU_SO). Expected {expected:#x}. Found {rv:#x}");
}

pub(crate) fn login_context_specific(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let rv = unsafe {
        ykcs11::C_Login(
            session,
            CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
            DEFAULT_USER_PIN.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_USER_PIN.len() as CK_ULONG,
        )
    };
    assert_eq!(
        rv, expected,
        "C_Login(CKU_CONTEXT_SPECIFIC). Expected {expected:#x}. Found {rv:#x}"
    );
}



// /// Logs out of whatever role `h_session` currently holds (expected to be
// /// `CKU_SO`, from `open_so_session`) and logs back in as `CKU_USER` with the
// /// factory-default PIN -- the login state is mutually exclusive between the
// /// two roles on a given slot (`PivBackend::login`), so this can't just be
// /// layered on top of the existing SO session.
// pub(crate) fn switch_to_user_login(h_session: CK_SESSION_HANDLE) {
//     let rv = unsafe { ykcs11::C_Logout(h_session) };
//     assert_eq!(rv, CKR_OK as CK_RV, "C_Logout(CKU_SO)");
//
//     let rv = unsafe {
//         ykcs11::C_Login(
//             h_session,
//             CKU_USER as CK_USER_TYPE,
//             DEFAULT_USER_PIN.as_ptr() as CK_UTF8CHAR_PTR,
//             DEFAULT_USER_PIN.len() as CK_ULONG,
//         )
//     };
//     assert_eq!(rv, CKR_OK as CK_RV, "C_Login(CKU_USER)");
// }

pub(crate) fn close_session(h_session: CK_SESSION_HANDLE) {
    let rv = unsafe { ykcs11::C_Logout(h_session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout");
    let rv = unsafe { ykcs11::C_CloseSession(h_session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession");
}

/// Reads a single fixed-length attribute via `C_GetAttributeValue`.
/// `C_GetAttributeValue` writes the result directly into the buffer backing
/// `attr(...)`'s `pValue`
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
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_GetAttributeValue ({what})"));
    buf
}

pub(crate) fn find_object_handle(h_session: CK_SESSION_HANDLE, class: u32, id: u8, what: &str) -> CK_OBJECT_HANDLE {
    let class_bytes = ulong_bytes(class);
    let id_bytes = [id];
    let mut template = [attr(CKA_CLASS, &class_bytes), attr(CKA_ID, &id_bytes)];
    let rv = unsafe {
        ykcs11::C_FindObjectsInit(h_session, template.as_mut_ptr(), template.len() as CK_ULONG)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjectsInit ({what})"));

    let mut handles = [0 as CK_OBJECT_HANDLE; 1];
    let mut count: CK_ULONG = 0;
    let rv = unsafe {
        ykcs11::C_FindObjects(h_session, handles.as_mut_ptr(), handles.len() as CK_ULONG, &mut count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjects ({what})"));
    assert_eq!(count, 1, "{what}: expected exactly one matching object, found {count}");

    let rv = unsafe { ykcs11::C_FindObjectsFinal(h_session) };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjectsFinal ({what})"));

    handles[0]
}

// /// A `CK_MECHANISM` with no parameter -- every mechanism these tests use
// /// (`CKM_ML_KEM`) takes none. Named `no_param_mechanism` rather than
// /// `mechanism` so call sites can freely use `mechanism` as a local variable
// /// name for the result without shadowing this function.
// pub(crate) fn no_param_mechanism(ty: u32) -> CK_MECHANISM {
//     CK_MECHANISM {
//         mechanism: ty as CK_MECHANISM_TYPE,
//         pParameter: ptr::null_mut(),
//         ulParameterLen: 0,
//     }
// }

// /// Calls `C_GetInterface("PKCS 11", NULL, ...)` and returns the full 3.2
// /// function table it points at. `C_EncapsulateKey`/`C_DecapsulateKey` are
// /// only reachable this way -- they aren't part of the legacy
// /// `CK_FUNCTION_LIST` `C_GetFunctionList` returns (see `crate`'s own module
// /// doc comment, and `dispatch.rs`'s own doc comment on `G_INTERFACES`) --
// /// so this exercises the actual interface-discovery mechanism those two
// /// functions need, rather than calling `ykcs11::C_EncapsulateKey` directly
// /// the way every other function here reaches `ykcs11`'s C ABI.
// pub(crate) fn get_3_2_function_list() -> &'static CK_FUNCTION_LIST_3_2 {
//     const INTERFACE_NAME: &[u8] = b"PKCS 11\0";
//     let mut p_interface: CK_INTERFACE_PTR = ptr::null_mut();
//     let rv = unsafe {
//         ykcs11::C_GetInterface(
//             INTERFACE_NAME.as_ptr() as CK_UTF8CHAR_PTR,
//             ptr::null_mut(),
//             &mut p_interface,
//             0,
//         )
//     };
//     assert_eq!(rv, CKR_OK as CK_RV, "C_GetInterface");
//     assert!(!p_interface.is_null(), "C_GetInterface returned a null interface");
//
//     let function_list = unsafe { (*p_interface).pFunctionList as *const CK_FUNCTION_LIST_3_2 };
//     assert!(!function_list.is_null(), "C_GetInterface returned a null function list");
//     unsafe { &*function_list }
// }

// /// Imports a private key via `C_CreateObject`, confirms the slot reports
// /// the expected `CKA_KEY_TYPE` back afterward (not just that the call
// /// returned `CKR_OK`, but that the import actually stuck on the device),
// /// and returns the new private-key object's handle.
// pub(crate) fn import_and_verify(
//     h_session: CK_SESSION_HANDLE,
//     id: u8,
//     key_type: u32,
//     parameter_set: u32,
//     seed: &[u8],
//     what: &str,
// ) -> CK_OBJECT_HANDLE {
//     let class = ulong_bytes(CKO_PRIVATE_KEY);
//     let key_type_bytes = ulong_bytes(key_type);
//     let id_bytes = [id];
//     let param_set_bytes = ulong_bytes(parameter_set);
//
//     let mut template = [
//         attr(CKA_CLASS, &class),
//         attr(CKA_KEY_TYPE, &key_type_bytes),
//         attr(CKA_ID, &id_bytes),
//         attr(CKA_PARAMETER_SET, &param_set_bytes),
//         attr(CKA_SEED, seed),
//     ];
//
//     let mut h_object: CK_OBJECT_HANDLE = 0;
//     let rv = unsafe {
//         ykcs11::C_CreateObject(
//             h_session,
//             template.as_mut_ptr(),
//             template.len() as CK_ULONG,
//             &mut h_object,
//         )
//     };
//     assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_CreateObject ({what})"));
//     assert_ne!(h_object, 0, "{what}: C_CreateObject returned a null handle");
//
//     let got_key_type = get_attribute(h_session, h_object, CKA_KEY_TYPE, key_type_bytes.len(), what);
//     assert_eq!(
//         got_key_type, key_type_bytes,
//         "{what}: CKA_KEY_TYPE readback mismatch after import"
//     );
//
//     h_object
// }

