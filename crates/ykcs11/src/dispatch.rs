// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! PKCS#11 C_xxx dispatch for the YubiKey PIV module. Session/slot
//! bookkeeping lives in the shared `pkcs11_common::backend::Engine`
//! (`crate::backend::G_ENGINE`); this file only wires the fixed C ABI entry
//! points to it.

use crate::backend::G_ENGINE;
use pkcs11_common::debug;
use pkcs11_common::function_list::{build_function_list, RealFunctions};
use pkcs11_sys::*;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    let dbg_level: u8 = std::env::var("YKCS11_DBG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    debug::set_verbose(dbg_level);
    G_ENGINE.initialize(pInitArgs)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    G_ENGINE.finalize(pReserved)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    G_ENGINE.get_info(pInfo)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut CK_FUNCTION_LIST_PTR) -> CK_RV {
    G_ENGINE.get_function_list(ppFunctionList, &G_FUNCTION_LIST)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    G_ENGINE.get_slot_list(tokenPresent, pSlotList, pulCount)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    G_ENGINE.get_slot_info(slotID, pInfo)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    G_ENGINE.get_token_info(slotID, pInfo)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    G_ENGINE.get_mechanism_list(slotID, pMechanismList, pulCount)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechanismType: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    G_ENGINE.get_mechanism_info(slotID, mechanismType, pInfo)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    G_ENGINE.open_session(slotID, flags, pApplication, Notify, phSession)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    G_ENGINE.close_session(hSession)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    G_ENGINE.close_all_sessions(slotID)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    G_ENGINE.get_session_info(hSession, pInfo)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    G_ENGINE.login(hSession, userType, pPin, ulPinLen)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    G_ENGINE.logout(hSession)
}

// ============================================================
// Function List
// ============================================================

static G_FUNCTION_LIST: CK_FUNCTION_LIST = build_function_list(RealFunctions {
    version: CK_VERSION { major: 3, minor: 0 },
    c_initialize: Some(C_Initialize),
    c_finalize: Some(C_Finalize),
    c_get_info: Some(C_GetInfo),
    c_get_function_list: Some(C_GetFunctionList),
    c_get_slot_list: Some(C_GetSlotList),
    c_get_slot_info: Some(C_GetSlotInfo),
    c_get_token_info: Some(C_GetTokenInfo),
    c_get_mechanism_list: Some(C_GetMechanismList),
    c_get_mechanism_info: Some(C_GetMechanismInfo),
    c_open_session: Some(C_OpenSession),
    c_close_session: Some(C_CloseSession),
    c_close_all_sessions: Some(C_CloseAllSessions),
    c_get_session_info: Some(C_GetSessionInfo),
    c_login: Some(C_Login),
    c_logout: Some(C_Logout),
});
