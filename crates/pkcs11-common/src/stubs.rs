// Copyright 2026 Yubico AB

//! Shared implementations of the `C_*` functions that no module has real
//! logic for yet. [`crate::function_list::build_function_list`] wires every
//! module's function table to these until the corresponding feature lands.

#![allow(non_snake_case)]

use pkcs11_sys::*;

pub unsafe extern "C" fn C_InitToken(_: CK_SLOT_ID, _: CK_UTF8CHAR_PTR, _: CK_ULONG, _: CK_UTF8CHAR_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_InitPIN(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SetPIN(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG, _: CK_UTF8CHAR_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetOperationState(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_SetOperationState(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_CreateObject(_: CK_SESSION_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_CopyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_DestroyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetObjectSize(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
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
pub unsafe extern "C" fn C_DeriveKey(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR, _: CK_OBJECT_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetFunctionStatus(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL.into() }
pub unsafe extern "C" fn C_CancelFunction(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL.into() }
pub unsafe extern "C" fn C_WaitForSlotEvent(_: CK_FLAGS, _: CK_SLOT_ID_PTR, _: CK_VOID_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetMechanismList(_: CK_SLOT_ID, _: CK_MECHANISM_TYPE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
pub unsafe extern "C" fn C_GetMechanismInfo(_: CK_SLOT_ID, _: CK_MECHANISM_TYPE, _: CK_MECHANISM_INFO_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED.into() }
