// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! PKCS#11 C_xxx dispatch entry points. Session/slot bookkeeping lives in
//! the shared `pkcs11_common::backend::Engine` (`crate::backend::G_ENGINE`);
//! this file only wires the fixed C ABI entry points to it.

use crate::backend::G_ENGINE;
use crate::{din, dout};
use pkcs11_common::function_list::{build_function_list, RealFunctions};
use pkcs11_sys::*;

/// Brackets a call into `G_ENGINE` with the same entry/exit tracing the
/// original C module printed around every `C_*` function (`DIN;`/`DOUT;`,
/// no return-code value). The function name is passed explicitly since Rust
/// has no `__func__` equivalent available from inside `din!`/`dout!`.
macro_rules! traced {
    ($name:literal, $body:expr) => {{
        din!($name);
        let rv: CK_RV = $body;
        dout!($name);
        rv
    }};
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    traced!("C_Initialize", G_ENGINE.initialize(pInitArgs))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    traced!("C_Finalize", G_ENGINE.finalize(pReserved))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    traced!("C_GetInfo", G_ENGINE.get_info(pInfo))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut CK_FUNCTION_LIST_PTR) -> CK_RV {
    traced!("C_GetFunctionList", G_ENGINE.get_function_list(ppFunctionList, &G_FUNCTION_LIST))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    traced!("C_GetSlotList", G_ENGINE.get_slot_list(tokenPresent, pSlotList, pulCount))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    traced!("C_GetSlotInfo", G_ENGINE.get_slot_info(slotID, pInfo))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    traced!("C_GetTokenInfo", G_ENGINE.get_token_info(slotID, pInfo))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    traced!("C_GetMechanismList", G_ENGINE.get_mechanism_list(slotID, pMechanismList, pulCount))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechanismType: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    traced!("C_GetMechanismInfo", G_ENGINE.get_mechanism_info(slotID, mechanismType, pInfo))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    traced!("C_OpenSession", G_ENGINE.open_session(slotID, flags, pApplication, Notify, phSession))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    traced!("C_CloseSession", G_ENGINE.close_session(hSession))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    traced!("C_CloseAllSessions", G_ENGINE.close_all_sessions(slotID))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    traced!("C_GetSessionInfo", G_ENGINE.get_session_info(hSession, pInfo))
}

/// The real PKCS#11 3.0 `C_LoginUser` — not part of the base `CK_FUNCTION_LIST`
/// (`CK_LoginUser` is a 3.0-only addition, reachable via `C_GetInterface`,
/// which this module doesn't implement), but exported directly and called
/// by `C_Login` below, exactly as `yubihsm_pkcs11.c` does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_LoginUser(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pUsername: CK_UTF8CHAR_PTR,
    ulUsernameLen: CK_ULONG,
) -> CK_RV {
    traced!(
        "C_LoginUser",
        G_ENGINE.login(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    // Matches yubihsm_pkcs11.c's C_Login (util_pkcs11.c isn't involved):
    // split the combined pPin buffer into a leading "identity" substring
    // (the optional '@'/'#label#' auth-scheme marker plus the 4-hex-digit
    // auth key ID) and a trailing password, then delegate to C_LoginUser.
    let mut username_len: CK_ULONG = 0;
    if !pPin.is_null() && ulPinLen > 0 {
        let pin_bytes = std::slice::from_raw_parts(pPin as *const u8, ulPinLen as usize);
        if pin_bytes[0] == b'@' {
            username_len += 1;
        } else if pin_bytes[0] == b'#' {
            username_len += 1;
            while username_len < ulPinLen && pin_bytes[username_len as usize] != b'#' {
                username_len += 1;
            }
            username_len += 1;
        }
        username_len += 4;
        if username_len > ulPinLen {
            username_len = ulPinLen;
        }
    }

    // Avoid offsetting a null pointer even by 0.
    let password_ptr = if pPin.is_null() { pPin } else { pPin.add(username_len as usize) };

    traced!(
        "C_Login",
        C_LoginUser(
            hSession,
            userType,
            password_ptr,
            ulPinLen - username_len,
            pPin,
            username_len,
        )
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    traced!("C_Logout", G_ENGINE.logout(hSession))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    pRandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    traced!(
        "C_GenerateRandom",
        G_ENGINE.generate_random(hSession, pRandomData, ulRandomLen)
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SeedRandom(
    hSession: CK_SESSION_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
) -> CK_RV {
    traced!("C_SeedRandom", G_ENGINE.seed_random(hSession, pSeed, ulSeedLen))
}

// ============================================================
// Function List (PKCS#11 3.0 compatible, using CK_FUNCTION_LIST)
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
    c_seed_random: Some(C_SeedRandom),
    c_generate_random: Some(C_GenerateRandom),
});
