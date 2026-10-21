// Copyright 2026 Yubico AB

//! Shared implementations of the `C_*` functions that no module has real
//! logic for yet. [`crate::function_list::build_function_list`] wires every
//! module's function table to these until the corresponding feature lands.

#![allow(non_snake_case)]

use pkcs11_sys::*;

pub unsafe extern "C" fn C_InitPIN(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetOperationState(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SetOperationState(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_CopyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetAttributeValue(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SetAttributeValue(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_FindObjectsInit(_: CK_SESSION_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_FindObjects(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE_PTR, _: CK_ULONG, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_FindObjectsFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DigestKey(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignRecoverInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignRecover(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifyRecoverInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifyRecover(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DigestEncryptUpdate(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DecryptDigestUpdate(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignEncryptUpdate(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DecryptVerifyUpdate(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GenerateKey(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_WrapKey(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_UnwrapKey(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetFunctionStatus(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL.into() }
pub unsafe extern "C" fn C_CancelFunction(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL.into() }
pub unsafe extern "C" fn C_WaitForSlotEvent(_: CK_FLAGS, _: CK_SLOT_ID_PTR, _: CK_VOID_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetMechanismList(_: CK_SLOT_ID, _: CK_MECHANISM_TYPE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetMechanismInfo(_: CK_SLOT_ID, _: CK_MECHANISM_TYPE, _: CK_MECHANISM_INFO_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }

// PKCS#11 3.0/3.2 additions -- only reachable via C_GetInterfaceList/
// C_GetInterface (see crate::function_list::build_function_list_3_2), and
// only by a module that opts into exposing that interface at all. None of
// these have real logic anywhere yet; C_EncapsulateKey/C_DecapsulateKey are
// the one pair with real implementations, wired directly by whichever
// module implements them rather than routed through here.
pub unsafe extern "C" fn C_LoginUser(_: CK_SESSION_HANDLE, _: CK_USER_TYPE, _: CK_UTF8CHAR_PTR, _: CK_ULONG, _: CK_UTF8CHAR_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SessionCancel(_: CK_SESSION_HANDLE, _: CK_FLAGS) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageEncryptInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_EncryptMessage(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_EncryptMessageBegin(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_EncryptMessageNext(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR, _: CK_FLAGS) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageEncryptFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageDecryptInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DecryptMessage(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DecryptMessageBegin(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DecryptMessageNext(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR, _: CK_FLAGS) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageDecryptFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageSignInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignMessage(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignMessageBegin(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SignMessageNext(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageSignFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageVerifyInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifyMessage(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifyMessageBegin(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifyMessageNext(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_MessageVerifyFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifySignatureInit(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifySignature(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifySignatureUpdate(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_VerifySignatureFinal(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetSessionValidationFlags(_: CK_SESSION_HANDLE, _: CK_SESSION_VALIDATION_FLAGS_TYPE, _: CK_FLAGS_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_AsyncComplete(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ASYNC_DATA_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_AsyncGetID(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_AsyncJoin(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_WrapKeyAuthenticated(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_UnwrapKeyAuthenticated(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
