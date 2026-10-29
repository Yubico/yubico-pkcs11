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

use crate::backend::G_ENGINE;
use pkcs11_common::debug;
use pkcs11_common::function_list::{RealFunctions, build_function_list, build_function_list_3_2};
use pkcs11_common::yk_dbg;
use pkcs11_sys::*;

/// Brackets a call into `G_ENGINE` with the same entry/exit tracing the
/// original C module printed around every `C_*` function (`DIN;`/`DOUT;`
/// plus a return-code log). The function name is passed explicitly rather
/// than relying on `din!`/`dout!`'s own `file!()`/`line!()` — those would
/// resolve to wherever `traced!` calls them, once, and every one of the ~14
/// call sites below would print the identical location. `rv` is a bare
/// PKCS#11 return-code number, not a symbolic name (e.g. `0` for `CKR_OK`).
macro_rules! traced {
    ($name:literal, $body:expr) => {{
        yk_dbg!("{}: in", $name);
        let rv: CK_RV = $body;
        yk_dbg!("{}: out, rv={}", $name, rv);
        rv
    }};
}

/// Forwards `yubikit`'s own `log::debug!`/`log::info!` calls (APDU-level
/// detail like "Authenticating with management key"/"Resetting PIV
/// application") to stderr, gated by the same `YKCS11_DBG` verbosity switch
/// as `yk_dbg!` -- without this, those calls are silently discarded, since
/// nothing otherwise installs a `log` backend. A dedicated logging crate
/// (e.g. `env_logger`) would be the usual choice here, but would need its
/// own `RUST_LOG` convention alongside this module's existing `YKCS11_DBG`
/// one; reusing the same switch (and the same `DBG:` prefix style as
/// `yk_dbg!`) is more consistent for this module's existing users.
///
/// `log::Level::Trace` is gated one tier higher (`YKCS11_DBG>=2`, via
/// `debug::is_trace_verbose()`) than everything else (`YKCS11_DBG>=1`) --
/// `yubikit`'s `log_traffic!` macro (raw APDU `SEND:`/`RECV:` hex dumps, see
/// `platform/pcsc.rs`) logs at `Trace`, and that's far noisier than its
/// regular `debug!`/`info!` messages, so it shouldn't turn on by default
/// just because some debug output was requested.
struct ForwardingLogger;

impl log::Log for ForwardingLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if metadata.level() == log::Level::Trace {
            debug::is_trace_verbose()
        } else {
            debug::is_verbose()
        }
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("DBG: [{}] {}: {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: ForwardingLogger = ForwardingLogger;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    unsafe {
        let dbg_level: u8 = std::env::var("YKCS11_DBG")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        debug::set_verbose(dbg_level);
        // Ignore the error: harmless if a logger is already installed (e.g.
        // a second C_Initialize after C_Finalize). The max-level filter is
        // set unconditionally, though (not just on the first successful
        // `set_logger`), so a later C_Initialize with a different
        // YKCS11_DBG value still takes effect -- `log::trace!` call sites
        // are skipped entirely below whatever `set_max_level` says, before
        // `ForwardingLogger::enabled`'s own per-record check ever runs.
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(if debug::is_trace_verbose() {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Debug
        });
        traced!("C_Initialize", G_ENGINE.initialize(pInitArgs))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    unsafe { traced!("C_Finalize", G_ENGINE.finalize(pReserved)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    unsafe { traced!("C_GetInfo", G_ENGINE.get_info(pInfo)) }
}

/// Backs `G_FUNCTION_LIST_3_2.C_GetInfo` specifically, reporting
/// `CRYPTOKI_VERSION_MAJOR`/`_MINOR` (3.2, from `pkcs11-sys`'s own vendored
/// OASIS header) instead of the legacy `CRYPTOKI_LEGACY_VERSION_MAJOR`/
/// `_MINOR` (2.40) the plain `C_GetInfo` above reports via
/// `PivBackend::library_info()` -- a caller that reached this module
/// through `C_GetInterface`'s 3.2 interface is talking to the
/// `CK_FUNCTION_LIST_3_2`-shaped table specifically, so `C_GetInfo` should
/// describe *that* table's version, not the legacy one's. Not a
/// `#[no_mangle]` export: nothing looks this up by symbol name, it's only
/// ever reached through `G_FUNCTION_LIST_3_2.C_GetInfo`'s function pointer.
unsafe extern "C" fn get_info_3_2(pInfo: CK_INFO_PTR) -> CK_RV {
    unsafe {
        traced!(
            "C_GetInfo",
            G_ENGINE.get_info_with_cryptoki_version(
                pInfo,
                (CRYPTOKI_VERSION_MAJOR as u8, CRYPTOKI_VERSION_MINOR as u8),
            )
        )
    }
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

/// PKCS#11 3.0 interface discovery -- the only way a real caller can reach
/// `C_EncapsulateKey`/`C_DecapsulateKey` at all, since `C_GetFunctionList`
/// above is contractually fixed at the 2.0 function set (see
/// `pkcs11_sys::function_list::CK_FUNCTION_LIST_3_2`'s own doc comment).
/// This module exposes exactly one interface, "PKCS 11" at version 3.2 (the
/// full superset), via `G_INTERFACES`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterfaceList(
    pInterfacesList: CK_INTERFACE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetInterfaceList",
            G_ENGINE.get_interface_list(pInterfacesList, pulCount, &G_INTERFACES.0)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
    pInterfaceName: CK_UTF8CHAR_PTR,
    pVersion: CK_VERSION_PTR,
    ppInterface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetInterface",
            G_ENGINE.get_interface(pInterfaceName, pVersion, ppInterface, &G_INTERFACES.0)
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_Login",
            G_ENGINE.login(hSession, userType, pPin, ulPinLen, std::ptr::null_mut(), 0)
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
pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_FindObjectsInit",
            G_ENGINE.find_objects_init(hSession, pTemplate, ulCount)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_FindObjects",
            G_ENGINE.find_objects(hSession, phObject, ulMaxObjectCount, pulObjectCount)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    unsafe { traced!("C_FindObjectsFinal", G_ENGINE.find_objects_final(hSession)) }
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
pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetAttributeValue",
            G_ENGINE.get_attribute_value(hSession, hObject, pTemplate, ulCount)
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
pub unsafe extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_GetObjectSize",
            G_ENGINE.get_object_size(hSession, hObject, pulSize)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DeriveKey",
            G_ENGINE.derive_key(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPublicKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    pulCiphertextLen: CK_ULONG_PTR,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_EncapsulateKey",
            G_ENGINE.encapsulate_key(
                hSession,
                pMechanism,
                hPublicKey,
                pTemplate,
                ulAttributeCount,
                pCiphertext,
                pulCiphertextLen,
                phKey,
            )
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DecapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPrivateKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    ulCiphertextLen: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    unsafe {
        traced!(
            "C_DecapsulateKey",
            G_ENGINE.decapsulate_key(
                hSession,
                pMechanism,
                hPrivateKey,
                pTemplate,
                ulAttributeCount,
                pCiphertext,
                ulCiphertextLen,
                phKey,
            )
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    unsafe { traced!("C_DestroyObject", G_ENGINE.destroy_object(hSession, hObject)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    pOldPin: CK_UTF8CHAR_PTR,
    ulOldLen: CK_ULONG,
    pNewPin: CK_UTF8CHAR_PTR,
    ulNewLen: CK_ULONG,
) -> CK_RV {
    unsafe {
        traced!(
            "C_SetPIN",
            G_ENGINE.set_pin(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen)
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    unsafe { traced!("C_InitToken", G_ENGINE.init_token(slotID, pPin, ulPinLen, pLabel)) }
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

// ============================================================
// Function List
// ============================================================

// `const`, not `static` -- referenced twice below (by `build_function_list`
// for the legacy 2.0-shaped table, and `build_function_list_3_2` for the
// full 3.2 one); a `const` is re-materialized at each use site, so this
// doesn't need a `Copy`/`Clone` derive on `RealFunctions` to be used twice.
const REAL: RealFunctions = RealFunctions {
    // The legacy `CK_FUNCTION_LIST` shape hasn't changed since Cryptoki
    // 2.40 -- matches `ykcs11.c`'s own `function_list.version` (not
    // `CRYPTOKI_VERSION_MAJOR`/`_MINOR`, which is 3.2 and only describes
    // the separate, newer `CK_FUNCTION_LIST_3_2` built below).
    version: CK_VERSION {
        major: CRYPTOKI_LEGACY_VERSION_MAJOR as u8,
        minor: CRYPTOKI_LEGACY_VERSION_MINOR as u8,
    },
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
    c_find_objects_init: Some(C_FindObjectsInit),
    c_find_objects: Some(C_FindObjects),
    c_find_objects_final: Some(C_FindObjectsFinal),
    c_get_attribute_value: Some(C_GetAttributeValue),
    c_digest_init: Some(C_DigestInit),
    c_digest: Some(C_Digest),
    c_digest_update: Some(C_DigestUpdate),
    c_digest_final: Some(C_DigestFinal),
    c_sign_init: Some(C_SignInit),
    c_sign: Some(C_Sign),
    c_sign_update: Some(C_SignUpdate),
    c_sign_final: Some(C_SignFinal),
    c_verify_init: Some(C_VerifyInit),
    c_verify: Some(C_Verify),
    c_verify_update: Some(C_VerifyUpdate),
    c_verify_final: Some(C_VerifyFinal),
    c_encrypt_init: Some(C_EncryptInit),
    c_encrypt: Some(C_Encrypt),
    c_encrypt_update: Some(C_EncryptUpdate),
    c_encrypt_final: Some(C_EncryptFinal),
    c_decrypt_init: Some(C_DecryptInit),
    c_decrypt: Some(C_Decrypt),
    c_decrypt_update: Some(C_DecryptUpdate),
    c_decrypt_final: Some(C_DecryptFinal),
    c_generate_key_pair: Some(C_GenerateKeyPair),
    c_create_object: Some(C_CreateObject),
    c_derive_key: Some(C_DeriveKey),
    c_get_object_size: Some(C_GetObjectSize),
    c_destroy_object: Some(C_DestroyObject),
    c_set_pin: Some(C_SetPIN),
    c_init_token: Some(C_InitToken),
    c_get_interface_list: Some(C_GetInterfaceList),
    c_get_interface: Some(C_GetInterface),
    c_encapsulate_key: Some(C_EncapsulateKey),
    c_decapsulate_key: Some(C_DecapsulateKey),
};

static G_FUNCTION_LIST: CK_FUNCTION_LIST = build_function_list(REAL);
// `build_function_list_3_2` always hardcodes its own `.version` field to
// {3, 2} regardless of `RealFunctions.version` -- but `C_GetInfo` doesn't
// get that same treatment (it's just a function pointer, copied verbatim
// from whichever `RealFunctions` value is passed in), so this needs its
// own `c_get_info` override to report {3, 2} too. See `get_info_3_2`'s own
// doc comment.
const REAL_3_2: RealFunctions = RealFunctions {
    c_get_info: Some(get_info_3_2),
    ..REAL
};
static G_FUNCTION_LIST_3_2: CK_FUNCTION_LIST_3_2 = build_function_list_3_2(REAL_3_2);

const PKCS11_INTERFACE_NAME: &[u8] = b"PKCS 11\0";

/// The interfaces `C_GetInterfaceList`/`C_GetInterface` report -- just the
/// one, "PKCS 11" at the full 3.2 function set. `pFunctionList` here is
/// exactly the pattern `CK_INTERFACE` is designed around: an opaque
/// `CK_VOID_PTR` a caller casts back to the right `CK_FUNCTION_LIST*` shape
/// based on the `version` embedded at its start (see `Engine::get_interface`
/// in pkcs11-common, which reads that same field generically).
///
/// Known, deliberate gap: there's no separate `CK_FUNCTION_LIST_3_0`/entry
/// at version `{3, 0}` -- since 3.2 is a strict superset of 3.0, any 3.0
/// call a caller might want to make already works against this one 3.2
/// table. The one caller this doesn't serve is one that calls
/// `C_GetInterface("PKCS 11", &{3, 0}, ...)` asking for *exactly* 3.0 (not
/// "give me whatever you've got," which `pVersion == NULL` already
/// satisfies) -- `Engine::get_interface`'s exact-version match rejects that
/// with `CKR_ARGUMENTS_BAD` today. Add a second `CK_FUNCTION_LIST_3_0`
/// struct/interface entry if that specific case ever needs to work.
///
/// Wrapped in `InterfaceTable` because `CK_INTERFACE` holds raw data
/// pointers (`pInterfaceName`/`pFunctionList`), which aren't `Sync` by
/// default -- unlike `CK_FUNCTION_LIST`'s fields, which are *function*
/// pointers (`Option<unsafe extern "C" fn(...)>`), auto-`Sync` regardless.
/// `static` requires `Sync`, so this needs an explicit (sound) opt-in: both
/// pointers here point at other `'static` data (`PKCS11_INTERFACE_NAME`,
/// `G_FUNCTION_LIST_3_2`) that's immutable for the life of the process, so
/// sharing read-only access to it across threads is safe.
struct InterfaceTable([CK_INTERFACE; 1]);
unsafe impl Sync for InterfaceTable {}

static G_INTERFACES: InterfaceTable = InterfaceTable([CK_INTERFACE {
    pInterfaceName: PKCS11_INTERFACE_NAME.as_ptr() as CK_UTF8CHAR_PTR,
    pFunctionList: &G_FUNCTION_LIST_3_2 as *const CK_FUNCTION_LIST_3_2 as CK_VOID_PTR,
    flags: 0,
}]);
