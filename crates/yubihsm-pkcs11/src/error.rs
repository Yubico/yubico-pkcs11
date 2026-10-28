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


use pkcs11_sys::*;

// /// Map a Result to CK_RV: Ok → CKR_OK, Err → the error code.
// pub fn rv_from_result(result: Result<(), CK_RV>) -> CK_RV {
//     match result {
//         Ok(()) => CKR_OK.into(),
//         Err(rv) => rv,
//     }
// }

/// Map a `yubihsmrs::Error` to a `CK_RV`. Currently only distinguishes
/// rejected-credentials failures (`CKR_PIN_INCORRECT`, matching
/// `token_login`/`C_LoginUser`'s handling of `YHR_CRYPTOGRAM_MISMATCH` /
/// `YHR_DEVICE_AUTHENTICATION_FAILED`) from everything else
/// (`CKR_DEVICE_ERROR`) — narrower than the C module's full `yrc_to_rv`
/// table, which maps ~30 distinct `yh_rc` codes to specific `CK_RV`s. Worth
/// building out to the full table once more yubihsmrs-backed operations
/// (beyond login/logout) need their own precise error codes.
pub fn hsm_error_to_rv(e: yubihsmrs::error::Error) -> CK_RV {
    if e.is_authentication_failure() {
        CKR_PIN_INCORRECT.into()
    } else {
        CKR_DEVICE_ERROR.into()
    }
}
