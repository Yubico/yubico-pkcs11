// Copyright 2026 Yubico AB

//! Mechanism classification shared by `C_Sign*`/`C_Verify*` — purely about
//! what a mechanism *means* (which hash, if any; which PSS params), not
//! which backend/key it's used with or what device call it drives. Lives
//! here (rather than duplicated between `ykcs11::sign` and a future
//! `ykcs11::verify`/`yubihsm-pkcs11` equivalent) since `verify_mechanism_init`
//! and `sign_mechanism_init` in the C reference accept the identical
//! mechanism set (confirmed byte-for-byte against both ykcs11.c and
//! yubihsm_pkcs11.c) — only the key-class/login checks around them differ,
//! and those stay in each backend's own orchestration code.

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
}

/// Matches `sign_mechanism_init`'s outer mechanism `switch`
/// (mechanisms.c:97-181) — confirmed identical to `verify_mechanism_init`'s
/// own outer switch (mechanisms.c:333-375): `CKM_RSA_X_509`/`CKM_RSA_PKCS`/
/// `CKM_RSA_PKCS_PSS`/`CKM_ECDSA`/`CKM_EDDSA` need no hash; the
/// `CKM_SHAx_RSA_PKCS`/`CKM_SHAx_RSA_PKCS_PSS`/`CKM_ECDSA_SHAx` mechanisms
/// pick a hash via `EVP_MD_by_mechanism` (mechanisms.c:48-65).
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
