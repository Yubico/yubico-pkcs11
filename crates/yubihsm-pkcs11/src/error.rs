// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

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
