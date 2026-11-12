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
/// no matter how many `#[test]` fns call this, then factory-resets the PIV
/// application exactly once too. The live PC/SC connection and PIV session
/// inside `ykcs11`'s own process-wide state then survive across every test,
/// so only the first test to actually need a connection pays for it.
/// `HARDWARE_LOCK` is already held by the caller before this runs, so
/// whichever test gets there first performs the real work and every other
/// test's call is a no-op.
pub(crate) fn ensure_initialized() {
    INIT.call_once(|| {
        let rv = unsafe { ykcs11::C_Initialize(ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");

        let slot_id = first_populated_slot();
        token_init(slot_id);
    });
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

pub(crate) fn logout(session: CK_SESSION_HANDLE, expected: CK_RV) {
    let rv = unsafe { ykcs11::C_Logout(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout. Expected {expected:#x}. Found {rv:#x}");
}

pub(crate) fn close_session(h_session: CK_SESSION_HANDLE) {
    // let rv = unsafe { ykcs11::C_Logout(h_session) };
    // assert_eq!(rv, CKR_OK as CK_RV, "C_Logout");
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
