// Copyright 2026 Yubico AB
// Licensed under the Apache License, Version 2.0

use pkcs11_sys::*;

/// Map a Result to CK_RV: Ok → CKR_OK, Err → the error code.
pub fn rv_from_result(result: Result<(), CK_RV>) -> CK_RV {
    match result {
        Ok(()) => CKR_OK.into(),
        Err(rv) => rv,
    }
}