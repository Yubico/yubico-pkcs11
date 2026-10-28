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


use super::*;

pub type CK_C_Initialize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_Finalize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_GetInfo = Option<unsafe extern "C" fn(CK_INFO_PTR) -> CK_RV>;
pub type CK_C_GetFunctionList = Option<unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV>;
pub type CK_C_GetSlotList =
    Option<unsafe extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetSlotInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, CK_SLOT_INFO_PTR) -> CK_RV>;
pub type CK_C_GetTokenInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, CK_TOKEN_INFO_PTR) -> CK_RV>;
pub type CK_C_GetMechanismList =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetMechanismInfo =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) -> CK_RV>;
pub type CK_C_InitToken =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV>;
pub type CK_C_InitPIN =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SetPIN = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_OpenSession = Option<
    unsafe extern "C" fn(
        CK_SLOT_ID,
        CK_FLAGS,
        CK_VOID_PTR,
        CK_NOTIFY,
        CK_SESSION_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_CloseSession = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CloseAllSessions = Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>;
pub type CK_C_GetSessionInfo =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) -> CK_RV>;
pub type CK_C_GetOperationState =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SetOperationState = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_Login = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_Logout = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CreateObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_CopyObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DestroyObject =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_GetObjectSize =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetAttributeValue = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_SetAttributeValue = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_FindObjectsInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_FindObjects = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV,
>;
pub type CK_C_FindObjectsFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_EncryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Encrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DecryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Decrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DigestInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV>;
pub type CK_C_Digest = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_DigestKey =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DigestFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Sign = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SignFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_SignRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_VerifyInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_Verify = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_VerifyUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_VerifyRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptDigestUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptVerifyUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKeyPair = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_WrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_UnwrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DeriveKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SeedRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GenerateRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GetFunctionStatus = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CancelFunction = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_WaitForSlotEvent =
    Option<unsafe extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV>;

/* ==============================================================
 * PKCS#11 3.0 additions (pkcs11f.h, guarded by `#ifndef
 * CK_PKCS11_2_0_ONLY`) -- included in CK_FUNCTION_LIST_3_0 and
 * CK_FUNCTION_LIST_3_2, but not the legacy CK_FUNCTION_LIST above.
 * ==============================================================
 */
pub type CK_C_GetInterfaceList =
    Option<unsafe extern "C" fn(CK_INTERFACE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetInterface = Option<
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV,
>;
pub type CK_C_LoginUser = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_USER_TYPE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_SessionCancel = Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_FLAGS) -> CK_RV>;
pub type CK_C_MessageEncryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_EncryptMessage = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptMessageBegin = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_EncryptMessageNext = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_FLAGS,
    ) -> CK_RV,
>;
pub type CK_C_MessageEncryptFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_MessageDecryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DecryptMessage = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptMessageBegin = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_DecryptMessageNext = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_FLAGS,
    ) -> CK_RV,
>;
pub type CK_C_MessageDecryptFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_MessageSignInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_SignMessage = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignMessageBegin =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SignMessageNext = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_MessageSignFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_MessageVerifyInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_VerifyMessage = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_VerifyMessageBegin =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyMessageNext = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_MessageVerifyFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;

/* ==============================================================
 * PKCS#11 3.2 additions (pkcs11f.h, guarded by `#ifndef
 * CK_PKCS11_3_0_ONLY`) -- included only in CK_FUNCTION_LIST_3_2.
 * ==============================================================
 */
pub type CK_C_EncapsulateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecapsulateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_VerifySignatureInit = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_VerifySignature =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifySignatureUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifySignatureFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_GetSessionValidationFlags = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_SESSION_VALIDATION_FLAGS_TYPE,
        CK_FLAGS_PTR,
    ) -> CK_RV,
>;
pub type CK_C_AsyncComplete = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ASYNC_DATA_PTR) -> CK_RV,
>;
pub type CK_C_AsyncGetID =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_AsyncJoin = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_WrapKeyAuthenticated = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_UnwrapKeyAuthenticated = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;

/* Same Windows-only 1-byte-packing convention as wrapper.h's pragma, applied
 * by hand here since this struct is hand-written, not bindgen-generated
 * (bindgen can't parse the macro-inclusion pattern the real headers use for
 * it). Without `packed` on Windows, `version` (2 bytes) gets padded to
 * align `C_Initialize` (an 8-byte function pointer) to offset 8 instead of
 * the spec's offset 2 — so any real caller reading through this table
 * (which every PKCS#11 consumer does, via C_GetFunctionList) reads garbage
 * function pointers and crashes calling through them. */
#[cfg_attr(windows, repr(packed))]
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: CK_C_Initialize,
    pub C_Finalize: CK_C_Finalize,
    pub C_GetInfo: CK_C_GetInfo,
    pub C_GetFunctionList: CK_C_GetFunctionList,
    pub C_GetSlotList: CK_C_GetSlotList,
    pub C_GetSlotInfo: CK_C_GetSlotInfo,
    pub C_GetTokenInfo: CK_C_GetTokenInfo,
    pub C_GetMechanismList: CK_C_GetMechanismList,
    pub C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub C_InitToken: CK_C_InitToken,
    pub C_InitPIN: CK_C_InitPIN,
    pub C_SetPIN: CK_C_SetPIN,
    pub C_OpenSession: CK_C_OpenSession,
    pub C_CloseSession: CK_C_CloseSession,
    pub C_CloseAllSessions: CK_C_CloseAllSessions,
    pub C_GetSessionInfo: CK_C_GetSessionInfo,
    pub C_GetOperationState: CK_C_GetOperationState,
    pub C_SetOperationState: CK_C_SetOperationState,
    pub C_Login: CK_C_Login,
    pub C_Logout: CK_C_Logout,
    pub C_CreateObject: CK_C_CreateObject,
    pub C_CopyObject: CK_C_CopyObject,
    pub C_DestroyObject: CK_C_DestroyObject,
    pub C_GetObjectSize: CK_C_GetObjectSize,
    pub C_GetAttributeValue: CK_C_GetAttributeValue,
    pub C_SetAttributeValue: CK_C_SetAttributeValue,
    pub C_FindObjectsInit: CK_C_FindObjectsInit,
    pub C_FindObjects: CK_C_FindObjects,
    pub C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub C_EncryptInit: CK_C_EncryptInit,
    pub C_Encrypt: CK_C_Encrypt,
    pub C_EncryptUpdate: CK_C_EncryptUpdate,
    pub C_EncryptFinal: CK_C_EncryptFinal,
    pub C_DecryptInit: CK_C_DecryptInit,
    pub C_Decrypt: CK_C_Decrypt,
    pub C_DecryptUpdate: CK_C_DecryptUpdate,
    pub C_DecryptFinal: CK_C_DecryptFinal,
    pub C_DigestInit: CK_C_DigestInit,
    pub C_Digest: CK_C_Digest,
    pub C_DigestUpdate: CK_C_DigestUpdate,
    pub C_DigestKey: CK_C_DigestKey,
    pub C_DigestFinal: CK_C_DigestFinal,
    pub C_SignInit: CK_C_SignInit,
    pub C_Sign: CK_C_Sign,
    pub C_SignUpdate: CK_C_SignUpdate,
    pub C_SignFinal: CK_C_SignFinal,
    pub C_SignRecoverInit: CK_C_SignRecoverInit,
    pub C_SignRecover: CK_C_SignRecover,
    pub C_VerifyInit: CK_C_VerifyInit,
    pub C_Verify: CK_C_Verify,
    pub C_VerifyUpdate: CK_C_VerifyUpdate,
    pub C_VerifyFinal: CK_C_VerifyFinal,
    pub C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub C_VerifyRecover: CK_C_VerifyRecover,
    pub C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub C_GenerateKey: CK_C_GenerateKey,
    pub C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub C_WrapKey: CK_C_WrapKey,
    pub C_UnwrapKey: CK_C_UnwrapKey,
    pub C_DeriveKey: CK_C_DeriveKey,
    pub C_SeedRandom: CK_C_SeedRandom,
    pub C_GenerateRandom: CK_C_GenerateRandom,
    pub C_GetFunctionStatus: CK_C_GetFunctionStatus,
    pub C_CancelFunction: CK_C_CancelFunction,
    pub C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

/// The full PKCS#11 3.2 function table -- every field `CK_FUNCTION_LIST`
/// has, plus all 24 functions PKCS#11 3.0 added and all 12 PKCS#11 3.2
/// added (in the exact order pkcs11f.h declares them; the real header
/// builds this by `#include`-ing pkcs11f.h a third time with neither the
/// `CK_PKCS11_2_0_ONLY` nor `CK_PKCS11_3_0_ONLY` guard set). Reachable only
/// via `C_GetInterfaceList`/`C_GetInterface` (PKCS#11 3.0+) -- unlike
/// `CK_FUNCTION_LIST`, this isn't something `C_GetFunctionList` can ever
/// return, since that function's contract is fixed at the 2.0 shape.
#[cfg_attr(windows, repr(packed))]
#[repr(C)]
pub struct CK_FUNCTION_LIST_3_2 {
    pub version: CK_VERSION,
    pub C_Initialize: CK_C_Initialize,
    pub C_Finalize: CK_C_Finalize,
    pub C_GetInfo: CK_C_GetInfo,
    pub C_GetFunctionList: CK_C_GetFunctionList,
    pub C_GetSlotList: CK_C_GetSlotList,
    pub C_GetSlotInfo: CK_C_GetSlotInfo,
    pub C_GetTokenInfo: CK_C_GetTokenInfo,
    pub C_GetMechanismList: CK_C_GetMechanismList,
    pub C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub C_InitToken: CK_C_InitToken,
    pub C_InitPIN: CK_C_InitPIN,
    pub C_SetPIN: CK_C_SetPIN,
    pub C_OpenSession: CK_C_OpenSession,
    pub C_CloseSession: CK_C_CloseSession,
    pub C_CloseAllSessions: CK_C_CloseAllSessions,
    pub C_GetSessionInfo: CK_C_GetSessionInfo,
    pub C_GetOperationState: CK_C_GetOperationState,
    pub C_SetOperationState: CK_C_SetOperationState,
    pub C_Login: CK_C_Login,
    pub C_Logout: CK_C_Logout,
    pub C_CreateObject: CK_C_CreateObject,
    pub C_CopyObject: CK_C_CopyObject,
    pub C_DestroyObject: CK_C_DestroyObject,
    pub C_GetObjectSize: CK_C_GetObjectSize,
    pub C_GetAttributeValue: CK_C_GetAttributeValue,
    pub C_SetAttributeValue: CK_C_SetAttributeValue,
    pub C_FindObjectsInit: CK_C_FindObjectsInit,
    pub C_FindObjects: CK_C_FindObjects,
    pub C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub C_EncryptInit: CK_C_EncryptInit,
    pub C_Encrypt: CK_C_Encrypt,
    pub C_EncryptUpdate: CK_C_EncryptUpdate,
    pub C_EncryptFinal: CK_C_EncryptFinal,
    pub C_DecryptInit: CK_C_DecryptInit,
    pub C_Decrypt: CK_C_Decrypt,
    pub C_DecryptUpdate: CK_C_DecryptUpdate,
    pub C_DecryptFinal: CK_C_DecryptFinal,
    pub C_DigestInit: CK_C_DigestInit,
    pub C_Digest: CK_C_Digest,
    pub C_DigestUpdate: CK_C_DigestUpdate,
    pub C_DigestKey: CK_C_DigestKey,
    pub C_DigestFinal: CK_C_DigestFinal,
    pub C_SignInit: CK_C_SignInit,
    pub C_Sign: CK_C_Sign,
    pub C_SignUpdate: CK_C_SignUpdate,
    pub C_SignFinal: CK_C_SignFinal,
    pub C_SignRecoverInit: CK_C_SignRecoverInit,
    pub C_SignRecover: CK_C_SignRecover,
    pub C_VerifyInit: CK_C_VerifyInit,
    pub C_Verify: CK_C_Verify,
    pub C_VerifyUpdate: CK_C_VerifyUpdate,
    pub C_VerifyFinal: CK_C_VerifyFinal,
    pub C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub C_VerifyRecover: CK_C_VerifyRecover,
    pub C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub C_GenerateKey: CK_C_GenerateKey,
    pub C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub C_WrapKey: CK_C_WrapKey,
    pub C_UnwrapKey: CK_C_UnwrapKey,
    pub C_DeriveKey: CK_C_DeriveKey,
    pub C_SeedRandom: CK_C_SeedRandom,
    pub C_GenerateRandom: CK_C_GenerateRandom,
    pub C_GetFunctionStatus: CK_C_GetFunctionStatus,
    pub C_CancelFunction: CK_C_CancelFunction,
    pub C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
    // PKCS#11 3.0 additions.
    pub C_GetInterfaceList: CK_C_GetInterfaceList,
    pub C_GetInterface: CK_C_GetInterface,
    pub C_LoginUser: CK_C_LoginUser,
    pub C_SessionCancel: CK_C_SessionCancel,
    pub C_MessageEncryptInit: CK_C_MessageEncryptInit,
    pub C_EncryptMessage: CK_C_EncryptMessage,
    pub C_EncryptMessageBegin: CK_C_EncryptMessageBegin,
    pub C_EncryptMessageNext: CK_C_EncryptMessageNext,
    pub C_MessageEncryptFinal: CK_C_MessageEncryptFinal,
    pub C_MessageDecryptInit: CK_C_MessageDecryptInit,
    pub C_DecryptMessage: CK_C_DecryptMessage,
    pub C_DecryptMessageBegin: CK_C_DecryptMessageBegin,
    pub C_DecryptMessageNext: CK_C_DecryptMessageNext,
    pub C_MessageDecryptFinal: CK_C_MessageDecryptFinal,
    pub C_MessageSignInit: CK_C_MessageSignInit,
    pub C_SignMessage: CK_C_SignMessage,
    pub C_SignMessageBegin: CK_C_SignMessageBegin,
    pub C_SignMessageNext: CK_C_SignMessageNext,
    pub C_MessageSignFinal: CK_C_MessageSignFinal,
    pub C_MessageVerifyInit: CK_C_MessageVerifyInit,
    pub C_VerifyMessage: CK_C_VerifyMessage,
    pub C_VerifyMessageBegin: CK_C_VerifyMessageBegin,
    pub C_VerifyMessageNext: CK_C_VerifyMessageNext,
    pub C_MessageVerifyFinal: CK_C_MessageVerifyFinal,
    // PKCS#11 3.2 additions.
    pub C_EncapsulateKey: CK_C_EncapsulateKey,
    pub C_DecapsulateKey: CK_C_DecapsulateKey,
    pub C_VerifySignatureInit: CK_C_VerifySignatureInit,
    pub C_VerifySignature: CK_C_VerifySignature,
    pub C_VerifySignatureUpdate: CK_C_VerifySignatureUpdate,
    pub C_VerifySignatureFinal: CK_C_VerifySignatureFinal,
    pub C_GetSessionValidationFlags: CK_C_GetSessionValidationFlags,
    pub C_AsyncComplete: CK_C_AsyncComplete,
    pub C_AsyncGetID: CK_C_AsyncGetID,
    pub C_AsyncJoin: CK_C_AsyncJoin,
    pub C_WrapKeyAuthenticated: CK_C_WrapKeyAuthenticated,
    pub C_UnwrapKeyAuthenticated: CK_C_UnwrapKeyAuthenticated,
}

pub type CK_FUNCTION_LIST_3_2_PTR = *mut CK_FUNCTION_LIST_3_2;
pub type CK_FUNCTION_LIST_3_2_PTR_PTR = *mut CK_FUNCTION_LIST_3_2_PTR;
