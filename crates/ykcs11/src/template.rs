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


use pkcs11_common::session::LoginState;
use pkcs11_sys::*;
use yubikit::piv::{PinPolicy, TouchPolicy};

/// `prime256v1`/P-256 (1.2.840.10045.3.1.7) as a DER `OBJECT IDENTIFIER` —
/// independently re-derived via base-128 arc encoding (not transcribed):
/// first arc pair `1,2` → `40*1+2 = 42 = 0x2A`; `840` → `0x86,0x48`
/// (6*128+72); `10045` → `0xCE,0x3D` (78*128+61, continuation bit set on
/// `0xCE`); `3,1,7` → `0x03,0x01,0x07`.
pub(crate) const P256_CURVE_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `secp384r1`/P-384 (1.3.132.0.34) as a DER `OBJECT IDENTIFIER` — same
/// re-derivation: `1,3` → `40*1+3 = 43 = 0x2B`; `132` → `0x81,0x04`
/// (1*128+4); `0` → `0x00`; `34` → `0x22`.
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

/// `CKA_YUBICO_PIN_POLICY`/`CKA_YUBICO_TOUCH_POLICY` (objects.c:3047-3079),
/// plus `CKA_ALWAYS_AUTHENTICATE` forcing `PinPolicy::Always` (objects.c:
/// 3023-3046) — conflicting with an already-explicit non-`Always` pin
/// policy is `CKR_TEMPLATE_INCONSISTENT`. Shared by `C_GenerateKeyPair`'s
/// private-key template and `C_CreateObject`'s `CKO_PRIVATE_KEY` import
/// template — both accept the identical set of policy attributes.
pub(crate) fn resolve_policies(
    private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> Result<(PinPolicy, TouchPolicy), CK_RV> {
    let mut pin_policy = match find_byte(private_key_template, crate::objects::CKA_YUBICO_PIN_POLICY)? {
        Some(b) => PinPolicy::from_u8(b).ok_or(CK_RV::from(CKR_ATTRIBUTE_VALUE_INVALID))?,
        None => PinPolicy::Default,
    };
    let touch_policy = match find_byte(private_key_template, crate::objects::CKA_YUBICO_TOUCH_POLICY)? {
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

/// Matches `do_check_public_exponent` — the device always uses 65537
/// internally, so a caller's `CKA_PUBLIC_EXPONENT` is just a sanity check
/// against asking for something it won't get. `CKA_PUBLIC_EXPONENT` is a
/// raw big-endian byte string per the PKCS#11 spec (arbitrary length,
/// possibly leading-zero-padded) -- *not* a native `CK_ULONG`, so this
/// compares bytes directly rather than padding into a `CK_ULONG`-sized
/// buffer and reinterpreting (which previously hardcoded an 8-byte pad,
/// silently assuming `CK_ULONG` is always 8 bytes -- true on Linux/macOS's
/// LP64 `unsigned long`, but `CK_ULONG` is only 4 bytes on Windows's LLP64
/// one, where that padding would always fail to convert and reject every
/// otherwise-valid RSA template).
pub(crate) fn is_public_exponent_65537(e: &[u8]) -> bool {
    let trimmed = match e.iter().position(|&b| b != 0) {
        Some(i) => &e[i..],
        None => &[][..],
    };
    trimmed == [0x01, 0x00, 0x01]
}

/// `slot.login_state != LoginState::SO` → `CKR_USER_TYPE_INVALID`, the
/// login requirement shared by `C_GenerateKeyPair` (ykcs11.c:3587-3592) and
/// `C_CreateObject` (ykcs11.c:1499-1504/1604-1609) alike — both are
/// card-management operations, unlike `C_Sign*`/`C_Verify*`'s PIN-only (or
/// no-login) requirements.
pub(crate) fn require_so_login(login_state: LoginState) -> Result<(), CK_RV> {
    if login_state != LoginState::SO {
        return Err(CKR_USER_TYPE_INVALID.into());
    }
    Ok(())
}
