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


use pkcs11_sys::*;

/// Every mechanism this project signs/verifies with, classified by what it
/// needs done to the accumulated data before the device/host crypto call —
/// independent of which key it's used with (that's checked separately,
/// against the object's actual key material).
pub enum MechanismKind {
    RsaX509,
    RsaPkcs1Raw,
    RsaPkcs1Hashed(CK_MECHANISM_TYPE),
    RsaPssRaw,
    RsaPssHashed(CK_MECHANISM_TYPE),
    EcdsaRaw,
    EcdsaHashed(CK_MECHANISM_TYPE),
    Eddsa,
    /// `CKM_ML_DSA` — no C reference, see this module's own doc comment.
    MlDsa,
}

/// Matches `sign_mechanism_init`'s outer mechanism `switch`
/// (mechanisms.c:97-181) — confirmed identical to `verify_mechanism_init`'s
/// own outer switch (mechanisms.c:333-375): `CKM_RSA_X_509`/`CKM_RSA_PKCS`/
/// `CKM_RSA_PKCS_PSS`/`CKM_ECDSA`/`CKM_EDDSA` need no hash; the
/// `CKM_SHAx_RSA_PKCS`/`CKM_SHAx_RSA_PKCS_PSS`/`CKM_ECDSA_SHAx` mechanisms
/// pick a hash via `EVP_MD_by_mechanism` (mechanisms.c:48-65). `CKM_ML_DSA`
/// is the one addition neither C reference has, folded in anyway (see this
/// module's own doc comment).
pub fn classify_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<MechanismKind> {
    Some(match mechanism as u32 {
        CKM_RSA_X_509 => MechanismKind::RsaX509,
        CKM_RSA_PKCS => MechanismKind::RsaPkcs1Raw,
        CKM_SHA1_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_SHA256_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_SHA384_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_SHA512_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_RSA_PKCS_PSS => MechanismKind::RsaPssRaw,
        CKM_SHA1_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_SHA256_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_SHA384_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_SHA512_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_ECDSA => MechanismKind::EcdsaRaw,
        CKM_ECDSA_SHA1 => MechanismKind::EcdsaHashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA256 => MechanismKind::EcdsaHashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA384 => MechanismKind::EcdsaHashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA512 => MechanismKind::EcdsaHashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_EDDSA => MechanismKind::Eddsa,
        CKM_ML_DSA => MechanismKind::MlDsa,
        _ => return None,
    })
}

/// `pss->hashAlg` is itself already a `CKM_SHA*` value per spec — this
/// reuses `DigestOp`'s own hash support (SHA-1/256/384/512 only) rather
/// than a separate allowlist, matching `EVP_MD_by_mechanism`'s set of
/// `CKM_SHA*` cases (mechanisms.c:48-65).
fn is_supported_pss_hash(hash_mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        hash_mechanism as u32,
        CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512
    )
}

/// `pss->mgf` uses the separate `CKG_MGF1_SHA*` constant space rather than
/// `CKM_SHA*` — matches `EVP_MD_by_mechanism`'s `CKG_MGF1_SHA*` cases
/// (mechanisms.c:52,55,58,61). `CKG_MGF1_SHA224`/`CKG_MGF1_SHA3_*` are
/// accepted by the C reference's MGF1 but not here, matching the same
/// SHA-1/256/384/512-only scope as every other hash use in this project.
fn mgf_hash_mechanism(mgf: CK_RSA_PKCS_MGF_TYPE) -> Option<CK_MECHANISM_TYPE> {
    Some(match mgf as u32 {
        CKG_MGF1_SHA1 => CKM_SHA_1,
        CKG_MGF1_SHA256 => CKM_SHA256,
        CKG_MGF1_SHA384 => CKM_SHA384,
        CKG_MGF1_SHA512 => CKM_SHA512,
        _ => return None,
    } as CK_MECHANISM_TYPE)
}

/// Reads and validates `CK_RSA_PKCS_PSS_PARAMS` out of a mechanism's raw
/// `pParameter` bytes — matches `sign_mechanism_init`'s own PSS case
/// (mechanisms.c:159-179), which `verify_mechanism_init` shares byte-for-byte
/// (mechanisms.c:413-480): exact-size parameter required
/// (`CKR_MECHANISM_PARAM_INVALID`), `hashAlg`/`mgf` must both resolve to a
/// supported hash, and — only when `required_hash` is `Some` (a combined
/// `CKM_SHAx_RSA_PKCS_PSS` mechanism) — `hashAlg` must match the outer
/// mechanism's own hash. All three failure cases return `CKR_ARGUMENTS_BAD`
/// in the C reference, not `CKR_MECHANISM_INVALID`/`CKR_MECHANISM_PARAM_INVALID`.
pub fn resolve_pss_params(
    parameter: &[u8],
    required_hash: Option<CK_MECHANISM_TYPE>,
) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, usize), CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length just checked above. CK_RSA_PKCS_PSS_PARAMS is a
    // `#[repr(C)]` plain-old-data struct of three integers; PKCS#11 callers
    // aren't guaranteed to hand us a suitably aligned pointer, hence
    // `read_unaligned` rather than a direct reference/dereference.
    let pss: CK_RSA_PKCS_PSS_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_RSA_PKCS_PSS_PARAMS) };

    if !is_supported_pss_hash(pss.hashAlg) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mgf_hash = mgf_hash_mechanism(pss.mgf).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
    if let Some(required) = required_hash {
        if pss.hashAlg != required {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
    }

    Ok((pss.hashAlg, mgf_hash, pss.sLen as usize))
}

/// Every mechanism `C_Decrypt*` supports — a disjoint set from
/// `MechanismKind` (no ECDSA/EdDSA/PSS; adds OAEP, which `C_Sign*` has no
/// equivalent of) matching `decrypt_mechanism_init`
/// (mechanisms.c:684-729).
pub enum CryptMechanismKind {
    RsaX509,
    RsaPkcs1,
    RsaOaep,
}

pub fn classify_crypt_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<CryptMechanismKind> {
    Some(match mechanism as u32 {
        CKM_RSA_X_509 => CryptMechanismKind::RsaX509,
        CKM_RSA_PKCS => CryptMechanismKind::RsaPkcs1,
        CKM_RSA_PKCS_OAEP => CryptMechanismKind::RsaOaep,
        _ => return None,
    })
}

/// Reads `CK_RSA_PKCS_OAEP_PARAMS` out of a mechanism's raw `pParameter`
/// bytes, returning `(hashAlg, mgf hash, label bytes)` — matches
/// `decrypt_mechanism_init`'s OAEP case (mechanisms.c:704-722). Unlike
/// `CK_RSA_PKCS_PSS_PARAMS`, this struct carries an out-of-line label
/// (`pSourceData`/`ulSourceDataLen`, used only when `source ==
/// CKZ_DATA_SPECIFIED`) — a second, separate raw pointer the caller gives
/// us, not bytes embedded in `parameter` itself.
pub fn resolve_oaep_params(parameter: &[u8]) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, Vec<u8>), CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length just checked above; read_unaligned for the same reason
    // as `resolve_pss_params` (PKCS#11 callers aren't guaranteed to hand us
    // an aligned pointer).
    let oaep: CK_RSA_PKCS_OAEP_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_RSA_PKCS_OAEP_PARAMS) };

    if !is_supported_pss_hash(oaep.hashAlg) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mgf_hash = mgf_hash_mechanism(oaep.mgf).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;

    let label = if oaep.source == 0 || oaep.ulSourceDataLen == 0 {
        // `source == 0` ("empty"/unspecified) and an explicit
        // `CKZ_DATA_SPECIFIED` source with a zero-length label are
        // equivalent here — both mean "no label", matching OAEP's own
        // default of an empty string when none is given.
        Vec::new()
    } else if oaep.source == CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
        if oaep.pSourceData.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        // SAFETY: `pSourceData`/`ulSourceDataLen` are a second
        // caller-supplied pointer+length pair, out-of-line from `parameter`
        // itself — same trust boundary as `parameter` (a PKCS#11 caller is
        // expected to keep it valid for the duration of this call).
        unsafe {
            std::slice::from_raw_parts(oaep.pSourceData as *const u8, oaep.ulSourceDataLen as usize)
                .to_vec()
        }
    } else {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    };

    Ok((oaep.hashAlg, mgf_hash, label))
}
