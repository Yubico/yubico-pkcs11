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

use pkcs11_common::session::LoginState;
use pkcs11_sys::*;
use yubikit::piv::{PinPolicy, TouchPolicy};

/// `prime256v1`/P-256 (1.2.840.10045.3.1.7) as a DER `OBJECT IDENTIFIER`
pub(crate) const P256_CURVE_OID: &[u8] =
    &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// `secp384r1`/P-384 (1.3.132.0.34) as a DER `OBJECT IDENTIFIER`
pub(crate) const P384_CURVE_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

pub(crate) fn find_attr<'a>(
    template: &'a [(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attr: u32,
) -> Option<&'a [u8]> {
    template
        .iter()
        .find(|(t, _)| *t == attr as CK_ATTRIBUTE_TYPE)
        .map(|(_, v)| v.as_slice())
}

pub(crate) fn find_byte(
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    attr: u32,
) -> Result<Option<u8>, CK_RV> {
    match find_attr(template, attr) {
        Some(bytes) => Ok(Some(
            *bytes
                .first()
                .ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
        )),
        None => Ok(None),
    }
}

/// Parse `CKA_YUBICO_PIN_POLICY`, `CKA_YUBICO_TOUCH_POLICY` and `CKA_ALWAYS_AUTHENTICATE`
pub(crate) fn resolve_policies(
    private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(PinPolicy, TouchPolicy), CK_RV> {
    let mut pin_policy =
        match find_byte(private_key_template, crate::objects::CKA_YUBICO_PIN_POLICY)? {
            Some(b) => PinPolicy::from_u8(b).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
            None => PinPolicy::Default,
        };
    let touch_policy = match find_byte(
        private_key_template,
        crate::objects::CKA_YUBICO_TOUCH_POLICY,
    )? {
        Some(b) => TouchPolicy::from_u8(b).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
        None => TouchPolicy::Default,
    };
    if let Some(always) = find_byte(private_key_template, CKA_ALWAYS_AUTHENTICATE)? {
        if always != 0 {
            match pin_policy {
                PinPolicy::Default => pin_policy = PinPolicy::Always,
                PinPolicy::Always => {}
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            }
        } else if matches!(pin_policy, PinPolicy::Always) {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
    }
    Ok((pin_policy, touch_policy))
}

pub(crate) fn is_public_exponent_65537(e: &[u8]) -> bool {
    let trimmed = match e.iter().position(|&b| b != 0) {
        Some(i) => &e[i..],
        None => &[][..],
    };
    trimmed == [0x01, 0x00, 0x01]
}

pub(crate) fn require_so_login(login_state: LoginState) -> Result<(), CK_RV> {
    if login_state != LoginState::SO {
        return Err(CKR_USER_TYPE_INVALID.into());
    }
    Ok(())
}
