// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

//! PKCS#11 C_xxx dispatch entry points. Session/slot bookkeeping lives in
//! the shared `pkcs11_common::backend::Engine` (`crate::backend::G_ENGINE`);
//! this file only wires the fixed C ABI entry points to it.

use crate::backend::G_ENGINE;
use crate::{din, dout};
use pkcs11_common::function_list::{RealFunctions, build_function_list};
use pkcs11_common::stubs;
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
    unsafe { traced!("C_Initialize", G_ENGINE.initialize(pInitArgs)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    unsafe { traced!("C_Finalize", G_ENGINE.finalize(pReserved)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    unsafe { traced!("C_GetInfo", G_ENGINE.get_info(pInfo)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut CK_FUNCTION_LIST_PTR) -> CK_RV {
    unsafe {
        traced!(
            "C_GetFunctionList",
            G_ENGINE.get_function_list(ppFunctionList, &G_FUNCTION_LIST)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetSlotList",
            G_ENGINE.get_slot_list(tokenPresent, pSlotList, pulCount)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    unsafe { traced!("C_GetSlotInfo", G_ENGINE.get_slot_info(slotID, pInfo)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    unsafe { traced!("C_GetTokenInfo", G_ENGINE.get_token_info(slotID, pInfo)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetMechanismList",
            G_ENGINE.get_mechanism_list(slotID, pMechanismList, pulCount)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechanismType: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetMechanismInfo",
            G_ENGINE.get_mechanism_info(slotID, mechanismType, pInfo)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_OpenSession",
            G_ENGINE.open_session(slotID, flags, pApplication, Notify, phSession)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    unsafe { traced!("C_CloseSession", G_ENGINE.close_session(hSession)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    unsafe { traced!("C_CloseAllSessions", G_ENGINE.close_all_sessions(slotID)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetSessionInfo",
            G_ENGINE.get_session_info(hSession, pInfo)
        )
    }
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
    unsafe {
        traced!(
            "C_LoginUser",
            G_ENGINE.login(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    unsafe {
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
        let password_ptr = if pPin.is_null() {
            pPin
        } else {
            pPin.add(username_len as usize)
        };

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
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    unsafe { traced!("C_Logout", G_ENGINE.logout(hSession)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    pRandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GenerateRandom",
            G_ENGINE.generate_random(hSession, pRandomData, ulRandomLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SeedRandom(
    hSession: CK_SESSION_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_SeedRandom",
            G_ENGINE.seed_random(hSession, pSeed, ulSeedLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DigestInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    unsafe { traced!("C_DigestInit", G_ENGINE.digest_init(hSession, pMechanism)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Digest",
            G_ENGINE.digest(hSession, pData, ulDataLen, pDigest, pulDigestLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DigestUpdate",
            G_ENGINE.digest_update(hSession, pPart, ulPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DigestFinal",
            G_ENGINE.digest_final(hSession, pDigest, pulDigestLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    unsafe { traced!("C_SignInit", G_ENGINE.sign_init(hSession, pMechanism, hKey)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Sign",
            G_ENGINE.sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_SignUpdate",
            G_ENGINE.sign_update(hSession, pPart, ulPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_SignFinal",
            G_ENGINE.sign_final(hSession, pSignature, pulSignatureLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    unsafe { traced!("C_VerifyInit", G_ENGINE.verify_init(hSession, pMechanism, hKey)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Verify",
            G_ENGINE.verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_VerifyUpdate",
            G_ENGINE.verify_update(hSession, pPart, ulPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_VerifyFinal",
            G_ENGINE.verify_final(hSession, pSignature, ulSignatureLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    unsafe { traced!("C_EncryptInit", G_ENGINE.encrypt_init(hSession, pMechanism, hKey)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Encrypt",
            G_ENGINE.encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_EncryptUpdate",
            G_ENGINE.encrypt_update(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_EncryptFinal",
            G_ENGINE.encrypt_final(hSession, pLastEncryptedPart, pulLastEncryptedPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_CreateObject",
            G_ENGINE.create_object(hSession, pTemplate, ulCount, phObject)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GenerateKeyPair",
            G_ENGINE.generate_key_pair(
                hSession,
                pMechanism,
                pPublicKeyTemplate,
                ulPublicKeyAttributeCount,
                pPrivateKeyTemplate,
                ulPrivateKeyAttributeCount,
                phPublicKey,
                phPrivateKey,
            )
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    unsafe { traced!("C_DecryptInit", G_ENGINE.decrypt_init(hSession, pMechanism, hKey)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Decrypt",
            G_ENGINE.decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DecryptUpdate",
            G_ENGINE.decrypt_update(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DecryptFinal",
            G_ENGINE.decrypt_final(hSession, pLastPart, pulLastPartLen)
        )
    }
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
    // Object enumeration isn't implemented for yubihsm-pkcs11 yet — keep
    // these wired to the shared not-yet-implemented stubs.
    c_find_objects_init: Some(stubs::C_FindObjectsInit),
    c_find_objects: Some(stubs::C_FindObjects),
    c_find_objects_final: Some(stubs::C_FindObjectsFinal),
    c_get_attribute_value: Some(stubs::C_GetAttributeValue),
    c_digest_init: Some(C_DigestInit),
    c_digest: Some(C_Digest),
    c_digest_update: Some(C_DigestUpdate),
    c_digest_final: Some(C_DigestFinal),
    // Signing isn't implemented for yubihsm-pkcs11 yet — these route
    // through the shared engine, which falls back to
    // CKR_FUNCTION_NOT_SUPPORTED via Backend::sign_init's default impl
    // since YubiHsmBackend doesn't override it.
    c_sign_init: Some(C_SignInit),
    c_sign: Some(C_Sign),
    c_sign_update: Some(C_SignUpdate),
    c_sign_final: Some(C_SignFinal),
    // Verification isn't implemented for yubihsm-pkcs11 yet (see
    // pkcs11-common's verify.rs doc comment) — these route through the
    // shared engine, which falls back to CKR_FUNCTION_NOT_SUPPORTED via
    // Backend::verify_init's default impl since YubiHsmBackend doesn't
    // override it.
    c_verify_init: Some(C_VerifyInit),
    c_verify: Some(C_Verify),
    c_verify_update: Some(C_VerifyUpdate),
    c_verify_final: Some(C_VerifyFinal),
    // Encryption/decryption aren't implemented for yubihsm-pkcs11 yet (same
    // object-model gap as Sign/Verify) — these route through the shared
    // engine, which falls back to CKR_FUNCTION_NOT_SUPPORTED via
    // Backend::encrypt_init's/decrypt_init's default impls since
    // YubiHsmBackend doesn't override them.
    c_encrypt_init: Some(C_EncryptInit),
    c_encrypt: Some(C_Encrypt),
    c_encrypt_update: Some(C_EncryptUpdate),
    c_encrypt_final: Some(C_EncryptFinal),
    c_decrypt_init: Some(C_DecryptInit),
    c_decrypt: Some(C_Decrypt),
    c_decrypt_update: Some(C_DecryptUpdate),
    c_decrypt_final: Some(C_DecryptFinal),
    // Key generation isn't implemented for yubihsm-pkcs11 yet (same
    // object-model gap as Sign/Verify/Encrypt/Decrypt) — routes through the
    // shared engine, which falls back to CKR_FUNCTION_NOT_SUPPORTED via
    // Backend::generate_key_pair's default impl since YubiHsmBackend
    // doesn't override it.
    c_generate_key_pair: Some(C_GenerateKeyPair),
    // Object creation/import isn't implemented for yubihsm-pkcs11 yet (same
    // object-model gap as everything else) — routes through the shared
    // engine, which falls back to CKR_FUNCTION_NOT_SUPPORTED via
    // Backend::create_object's default impl since YubiHsmBackend doesn't
    // override it.
    c_create_object: Some(C_CreateObject),
});
