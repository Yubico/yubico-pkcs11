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


use crate::stubs;
use pkcs11_sys::*;

/// The functions a module actually implements. Everything else in the
/// 68-entry Cryptoki function table is wired to a shared not-yet-implemented
/// stub from [`crate::stubs`].
pub struct RealFunctions {
    pub version: CK_VERSION,
    pub c_initialize: CK_C_Initialize,
    pub c_finalize: CK_C_Finalize,
    pub c_get_info: CK_C_GetInfo,
    pub c_get_function_list: CK_C_GetFunctionList,
    pub c_get_slot_list: CK_C_GetSlotList,
    pub c_get_slot_info: CK_C_GetSlotInfo,
    pub c_get_token_info: CK_C_GetTokenInfo,
    pub c_get_mechanism_list: CK_C_GetMechanismList,
    pub c_get_mechanism_info: CK_C_GetMechanismInfo,
    pub c_open_session: CK_C_OpenSession,
    pub c_close_session: CK_C_CloseSession,
    pub c_close_all_sessions: CK_C_CloseAllSessions,
    pub c_get_session_info: CK_C_GetSessionInfo,
    pub c_login: CK_C_Login,
    pub c_logout: CK_C_Logout,
    pub c_seed_random: CK_C_SeedRandom,
    pub c_generate_random: CK_C_GenerateRandom,
    pub c_find_objects_init: CK_C_FindObjectsInit,
    pub c_find_objects: CK_C_FindObjects,
    pub c_find_objects_final: CK_C_FindObjectsFinal,
    pub c_get_attribute_value: CK_C_GetAttributeValue,
    pub c_digest_init: CK_C_DigestInit,
    pub c_digest: CK_C_Digest,
    pub c_digest_update: CK_C_DigestUpdate,
    pub c_digest_final: CK_C_DigestFinal,
    pub c_sign_init: CK_C_SignInit,
    pub c_sign: CK_C_Sign,
    pub c_sign_update: CK_C_SignUpdate,
    pub c_sign_final: CK_C_SignFinal,
    pub c_verify_init: CK_C_VerifyInit,
    pub c_verify: CK_C_Verify,
    pub c_verify_update: CK_C_VerifyUpdate,
    pub c_verify_final: CK_C_VerifyFinal,
    pub c_encrypt_init: CK_C_EncryptInit,
    pub c_encrypt: CK_C_Encrypt,
    pub c_encrypt_update: CK_C_EncryptUpdate,
    pub c_encrypt_final: CK_C_EncryptFinal,
    pub c_decrypt_init: CK_C_DecryptInit,
    pub c_decrypt: CK_C_Decrypt,
    pub c_decrypt_update: CK_C_DecryptUpdate,
    pub c_decrypt_final: CK_C_DecryptFinal,
    pub c_generate_key_pair: CK_C_GenerateKeyPair,
    pub c_create_object: CK_C_CreateObject,
    pub c_derive_key: CK_C_DeriveKey,
    pub c_get_object_size: CK_C_GetObjectSize,
    pub c_destroy_object: CK_C_DestroyObject,
    pub c_set_pin: CK_C_SetPIN,
    pub c_init_token: CK_C_InitToken,
    /// PKCS#11 3.0/3.2 -- only read by [`build_function_list_3_2`], not the
    /// legacy [`build_function_list`]. `c_get_interface_list`/
    /// `c_get_interface` should point at
    /// `Engine::get_interface_list`/`get_interface`-backed entry points for
    /// any module exposing a 3.2 interface at all; `c_encapsulate_key`/
    /// `c_decapsulate_key` are `None` for a module that doesn't implement
    /// ML-KEM encapsulation.
    pub c_get_interface_list: CK_C_GetInterfaceList,
    pub c_get_interface: CK_C_GetInterface,
    pub c_encapsulate_key: CK_C_EncapsulateKey,
    pub c_decapsulate_key: CK_C_DecapsulateKey,
}

pub const fn build_function_list(real: RealFunctions) -> CK_FUNCTION_LIST {
    CK_FUNCTION_LIST {
        version: real.version,
        C_Initialize: real.c_initialize,
        C_Finalize: real.c_finalize,
        C_GetInfo: real.c_get_info,
        C_GetFunctionList: real.c_get_function_list,
        C_GetSlotList: real     .c_get_slot_list,
        C_GetSlotInfo: real.c_get_slot_info,
        C_GetTokenInfo: real.c_get_token_info,
        C_GetMechanismList: real.c_get_mechanism_list,
        C_GetMechanismInfo: real.c_get_mechanism_info,
        C_InitToken: real.c_init_token,
        C_InitPIN: Some(stubs::C_InitPIN),
        C_SetPIN: real.c_set_pin,
        C_OpenSession: real.c_open_session,
        C_CloseSession: real.c_close_session,
        C_CloseAllSessions: real.c_close_all_sessions,
        C_GetSessionInfo: real.c_get_session_info,
        C_GetOperationState: Some(stubs::C_GetOperationState),
        C_SetOperationState: Some(stubs::C_SetOperationState),
        C_Login: real.c_login,
        C_Logout: real.c_logout,
        C_CreateObject: real.c_create_object,
        C_CopyObject: Some(stubs::C_CopyObject),
        C_DestroyObject: real.c_destroy_object,
        C_GetObjectSize: real.c_get_object_size,
        C_GetAttributeValue: real.c_get_attribute_value,
        C_SetAttributeValue: Some(stubs::C_SetAttributeValue),
        C_FindObjectsInit: real.c_find_objects_init,
        C_FindObjects: real.c_find_objects,
        C_FindObjectsFinal: real.c_find_objects_final,
        C_EncryptInit: real.c_encrypt_init,
        C_Encrypt: real.c_encrypt,
        C_EncryptUpdate: real.c_encrypt_update,
        C_EncryptFinal: real.c_encrypt_final,
        C_DecryptInit: real.c_decrypt_init,
        C_Decrypt: real.c_decrypt,
        C_DecryptUpdate: real.c_decrypt_update,
        C_DecryptFinal: real.c_decrypt_final,
        C_DigestInit: real.c_digest_init,
        C_Digest: real.c_digest,
        C_DigestUpdate: real.c_digest_update,
        C_DigestKey: Some(stubs::C_DigestKey),
        C_DigestFinal: real.c_digest_final,
        C_SignInit: real.c_sign_init,
        C_Sign: real.c_sign,
        C_SignUpdate: real.c_sign_update,
        C_SignFinal: real.c_sign_final,
        C_SignRecoverInit: Some(stubs::C_SignRecoverInit),
        C_SignRecover: Some(stubs::C_SignRecover),
        C_VerifyInit: real.c_verify_init,
        C_Verify: real.c_verify,
        C_VerifyUpdate: real.c_verify_update,
        C_VerifyFinal: real.c_verify_final,
        C_VerifyRecoverInit: Some(stubs::C_VerifyRecoverInit),
        C_VerifyRecover: Some(stubs::C_VerifyRecover),
        C_DigestEncryptUpdate: Some(stubs::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(stubs::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(stubs::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(stubs::C_DecryptVerifyUpdate),
        C_GenerateKey: Some(stubs::C_GenerateKey),
        C_GenerateKeyPair: real.c_generate_key_pair,
        C_WrapKey: Some(stubs::C_WrapKey),
        C_UnwrapKey: Some(stubs::C_UnwrapKey),
        C_DeriveKey: real.c_derive_key,
        C_SeedRandom: real.c_seed_random,
        C_GenerateRandom: real.c_generate_random,
        C_GetFunctionStatus: Some(stubs::C_GetFunctionStatus),
        C_CancelFunction: Some(stubs::C_CancelFunction),
        C_WaitForSlotEvent: Some(stubs::C_WaitForSlotEvent),
    }
}

/// Builds the full PKCS#11 3.2 function table, reachable only via
/// `C_GetInterfaceList`/`C_GetInterface` (see
/// `pkcs11_common::backend::Engine::get_interface_list`/`get_interface`) --
/// unlike [`build_function_list`], which fills the legacy 2.0-shaped table
/// `C_GetFunctionList` returns. Every PKCS#11 3.0/3.2 function besides
/// `C_EncapsulateKey`/`C_DecapsulateKey` is wired to a shared not-yet-
/// implemented stub from [`crate::stubs`], same as the legacy table does for
/// functions this crate's callers haven't implemented.
pub const fn build_function_list_3_2(real: RealFunctions) -> CK_FUNCTION_LIST_3_2 {
    CK_FUNCTION_LIST_3_2 {
        version: CK_VERSION { major: 3, minor: 2 },
        C_Initialize: real.c_initialize,
        C_Finalize: real.c_finalize,
        C_GetInfo: real.c_get_info,
        C_GetFunctionList: real.c_get_function_list,
        C_GetSlotList: real.c_get_slot_list,
        C_GetSlotInfo: real.c_get_slot_info,
        C_GetTokenInfo: real.c_get_token_info,
        C_GetMechanismList: real.c_get_mechanism_list,
        C_GetMechanismInfo: real.c_get_mechanism_info,
        C_InitToken: real.c_init_token,
        C_InitPIN: Some(stubs::C_InitPIN),
        C_SetPIN: real.c_set_pin,
        C_OpenSession: real.c_open_session,
        C_CloseSession: real.c_close_session,
        C_CloseAllSessions: real.c_close_all_sessions,
        C_GetSessionInfo: real.c_get_session_info,
        C_GetOperationState: Some(stubs::C_GetOperationState),
        C_SetOperationState: Some(stubs::C_SetOperationState),
        C_Login: real.c_login,
        C_Logout: real.c_logout,
        C_CreateObject: real.c_create_object,
        C_CopyObject: Some(stubs::C_CopyObject),
        C_DestroyObject: real.c_destroy_object,
        C_GetObjectSize: real.c_get_object_size,
        C_GetAttributeValue: real.c_get_attribute_value,
        C_SetAttributeValue: Some(stubs::C_SetAttributeValue),
        C_FindObjectsInit: real.c_find_objects_init,
        C_FindObjects: real.c_find_objects,
        C_FindObjectsFinal: real.c_find_objects_final,
        C_EncryptInit: real.c_encrypt_init,
        C_Encrypt: real.c_encrypt,
        C_EncryptUpdate: real.c_encrypt_update,
        C_EncryptFinal: real.c_encrypt_final,
        C_DecryptInit: real.c_decrypt_init,
        C_Decrypt: real.c_decrypt,
        C_DecryptUpdate: real.c_decrypt_update,
        C_DecryptFinal: real.c_decrypt_final,
        C_DigestInit: real.c_digest_init,
        C_Digest: real.c_digest,
        C_DigestUpdate: real.c_digest_update,
        C_DigestKey: Some(stubs::C_DigestKey),
        C_DigestFinal: real.c_digest_final,
        C_SignInit: real.c_sign_init,
        C_Sign: real.c_sign,
        C_SignUpdate: real.c_sign_update,
        C_SignFinal: real.c_sign_final,
        C_SignRecoverInit: Some(stubs::C_SignRecoverInit),
        C_SignRecover: Some(stubs::C_SignRecover),
        C_VerifyInit: real.c_verify_init,
        C_Verify: real.c_verify,
        C_VerifyUpdate: real.c_verify_update,
        C_VerifyFinal: real.c_verify_final,
        C_VerifyRecoverInit: Some(stubs::C_VerifyRecoverInit),
        C_VerifyRecover: Some(stubs::C_VerifyRecover),
        C_DigestEncryptUpdate: Some(stubs::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(stubs::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(stubs::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(stubs::C_DecryptVerifyUpdate),
        C_GenerateKey: Some(stubs::C_GenerateKey),
        C_GenerateKeyPair: real.c_generate_key_pair,
        C_WrapKey: Some(stubs::C_WrapKey),
        C_UnwrapKey: Some(stubs::C_UnwrapKey),
        C_DeriveKey: real.c_derive_key,
        C_SeedRandom: real.c_seed_random,
        C_GenerateRandom: real.c_generate_random,
        C_GetFunctionStatus: Some(stubs::C_GetFunctionStatus),
        C_CancelFunction: Some(stubs::C_CancelFunction),
        C_WaitForSlotEvent: Some(stubs::C_WaitForSlotEvent),
        // PKCS#11 3.0 additions.
        C_GetInterfaceList: real.c_get_interface_list,
        C_GetInterface: real.c_get_interface,
        C_LoginUser: Some(stubs::C_LoginUser),
        C_SessionCancel: Some(stubs::C_SessionCancel),
        C_MessageEncryptInit: Some(stubs::C_MessageEncryptInit),
        C_EncryptMessage: Some(stubs::C_EncryptMessage),
        C_EncryptMessageBegin: Some(stubs::C_EncryptMessageBegin),
        C_EncryptMessageNext: Some(stubs::C_EncryptMessageNext),
        C_MessageEncryptFinal: Some(stubs::C_MessageEncryptFinal),
        C_MessageDecryptInit: Some(stubs::C_MessageDecryptInit),
        C_DecryptMessage: Some(stubs::C_DecryptMessage),
        C_DecryptMessageBegin: Some(stubs::C_DecryptMessageBegin),
        C_DecryptMessageNext: Some(stubs::C_DecryptMessageNext),
        C_MessageDecryptFinal: Some(stubs::C_MessageDecryptFinal),
        C_MessageSignInit: Some(stubs::C_MessageSignInit),
        C_SignMessage: Some(stubs::C_SignMessage),
        C_SignMessageBegin: Some(stubs::C_SignMessageBegin),
        C_SignMessageNext: Some(stubs::C_SignMessageNext),
        C_MessageSignFinal: Some(stubs::C_MessageSignFinal),
        C_MessageVerifyInit: Some(stubs::C_MessageVerifyInit),
        C_VerifyMessage: Some(stubs::C_VerifyMessage),
        C_VerifyMessageBegin: Some(stubs::C_VerifyMessageBegin),
        C_VerifyMessageNext: Some(stubs::C_VerifyMessageNext),
        C_MessageVerifyFinal: Some(stubs::C_MessageVerifyFinal),
        // PKCS#11 3.2 additions.
        C_EncapsulateKey: real.c_encapsulate_key,
        C_DecapsulateKey: real.c_decapsulate_key,
        C_VerifySignatureInit: Some(stubs::C_VerifySignatureInit),
        C_VerifySignature: Some(stubs::C_VerifySignature),
        C_VerifySignatureUpdate: Some(stubs::C_VerifySignatureUpdate),
        C_VerifySignatureFinal: Some(stubs::C_VerifySignatureFinal),
        C_GetSessionValidationFlags: Some(stubs::C_GetSessionValidationFlags),
        C_AsyncComplete: Some(stubs::C_AsyncComplete),
        C_AsyncGetID: Some(stubs::C_AsyncGetID),
        C_AsyncJoin: Some(stubs::C_AsyncJoin),
        C_WrapKeyAuthenticated: Some(stubs::C_WrapKeyAuthenticated),
        C_UnwrapKeyAuthenticated: Some(stubs::C_UnwrapKeyAuthenticated),
    }
}
