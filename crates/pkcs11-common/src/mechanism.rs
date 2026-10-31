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

use crate::ffi::in_slice_or_empty;
use pkcs11_sys::*;

/// A mechanism parameter as seen by a backend.
///
/// The engine copies PKCS#11 parameter structures that embed pointers into
/// owned values at the C boundary, so backends never dereference caller
/// memory. All other parameters are passed through as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MechanismParam {
    /// The `pParameter` bytes of any parameter not decoded below, including
    /// a malformed one; empty when absent.
    Bytes(Vec<u8>),
    /// `CK_RSA_PKCS_OAEP_PARAMS` for `CKM_RSA_PKCS_OAEP`.
    RsaOaep(RsaOaepParams),
    /// `CK_ECDH1_DERIVE_PARAMS` for `CKM_ECDH1_DERIVE`/`CKM_ECDH1_COFACTOR_DERIVE`.
    Ecdh1Derive(Ecdh1DeriveParams),
    /// `CK_SIGN_ADDITIONAL_CONTEXT` for `CKM_ML_DSA`.
    SignAdditionalContext(SignAdditionalContext),
}

impl MechanismParam {
    /// Whether the caller supplied no parameter.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Bytes(b) if b.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaOaepParams {
    pub hash_alg: CK_MECHANISM_TYPE,
    pub mgf: CK_RSA_PKCS_MGF_TYPE,
    pub source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    /// `pSourceData`, read only when `source` is `CKZ_DATA_SPECIFIED`.
    pub source_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ecdh1DeriveParams {
    pub kdf: CK_EC_KDF_TYPE,
    pub shared_data: Vec<u8>,
    pub public_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAdditionalContext {
    pub hedge_variant: CK_HEDGE_TYPE,
    pub context: Vec<u8>,
}

/// Copies a pointer/length pair nested inside a parameter structure. A null
/// pointer with a non-zero length is reported as an invalid parameter.
unsafe fn copy_nested(ptr: *const u8, len: CK_ULONG) -> Result<Vec<u8>, CK_RV> {
    unsafe { crate::ffi::in_slice(ptr, len) }
        .map(<[u8]>::to_vec)
        .map_err(|_| CKR_MECHANISM_PARAM_INVALID.into())
}

/// Reads a `#[repr(C)]` parameter structure from `raw` if the size matches.
fn read_struct<T: Copy>(raw: &[u8]) -> Option<T> {
    if raw.len() != size_of::<T>() {
        return None;
    }
    // SAFETY: `raw` holds exactly `size_of::<T>()` initialized bytes, and the
    // callers only instantiate `T` with plain C structures of integers and
    // raw pointers, for which every bit pattern is valid. PKCS#11 does not
    // promise an aligned `pParameter`, hence `read_unaligned`.
    Some(unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<T>()) })
}

/// Decodes a `CK_MECHANISM` parameter, deep-copying the pointer-bearing
/// structures listed on [`MechanismParam`]. A parameter of unexpected size is
/// passed through as [`MechanismParam::Bytes`] for the backend to reject.
///
/// # Safety
///
/// `ptr`/`len` must satisfy [`in_slice_or_empty`]'s contract, and every
/// non-null pointer/length pair nested inside a decoded structure must be
/// valid for reads of that many bytes.
pub unsafe fn decode_mechanism_param(
    mechanism: CK_MECHANISM_TYPE,
    ptr: *const u8,
    len: CK_ULONG,
) -> Result<MechanismParam, CK_RV> {
    let raw = unsafe { in_slice_or_empty(ptr, len)? };
    let decoded = match mechanism as u32 {
        CKM_RSA_PKCS_OAEP => read_struct::<CK_RSA_PKCS_OAEP_PARAMS>(raw).map(|p| {
            let source_data = if p.source != CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
                Vec::new()
            } else {
                unsafe { copy_nested(p.pSourceData as *const u8, p.ulSourceDataLen)? }
            };
            Ok::<_, CK_RV>(MechanismParam::RsaOaep(RsaOaepParams {
                hash_alg: p.hashAlg,
                mgf: p.mgf,
                source: p.source,
                source_data,
            }))
        }),
        CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => read_struct::<CK_ECDH1_DERIVE_PARAMS>(raw)
            .map(|p| unsafe {
                Ok(MechanismParam::Ecdh1Derive(Ecdh1DeriveParams {
                    kdf: p.kdf,
                    shared_data: copy_nested(p.pSharedData, p.ulSharedDataLen)?,
                    public_data: copy_nested(p.pPublicData, p.ulPublicDataLen)?,
                }))
            }),
        CKM_ML_DSA => read_struct::<CK_SIGN_ADDITIONAL_CONTEXT>(raw).map(|p| unsafe {
            Ok(MechanismParam::SignAdditionalContext(
                SignAdditionalContext {
                    hedge_variant: p.hedgeVariant,
                    context: copy_nested(p.pContext, p.ulContextLen)?,
                },
            ))
        }),
        _ => None,
    };
    decoded.unwrap_or_else(|| Ok(MechanismParam::Bytes(raw.to_vec())))
}

pub enum MechanismKind {
    RsaX509,
    RsaPkcs1Raw,
    RsaPkcs1Hashed(CK_MECHANISM_TYPE),
    RsaPssRaw,
    RsaPssHashed(CK_MECHANISM_TYPE),
    EcdsaRaw,
    EcdsaHashed(CK_MECHANISM_TYPE),
    Eddsa,
    MlDsa,
}

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

fn is_supported_pss_hash(hash_mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        hash_mechanism as u32,
        CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512
    )
}

fn mgf_hash_mechanism(mgf: CK_RSA_PKCS_MGF_TYPE) -> Option<CK_MECHANISM_TYPE> {
    Some(match mgf as u32 {
        CKG_MGF1_SHA1 => CKM_SHA_1,
        CKG_MGF1_SHA256 => CKM_SHA256,
        CKG_MGF1_SHA384 => CKM_SHA384,
        CKG_MGF1_SHA512 => CKM_SHA512,
        _ => return None,
    } as CK_MECHANISM_TYPE)
}

/// Validates `CK_RSA_PKCS_PSS_PARAMS` passed as a mechanism parameter
pub fn resolve_pss_params(
    parameter: &MechanismParam,
    required_hash: Option<CK_MECHANISM_TYPE>,
) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, usize), CK_RV> {
    let MechanismParam::Bytes(parameter) = parameter else {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    };
    let pss: CK_RSA_PKCS_PSS_PARAMS =
        read_struct(parameter).ok_or(CK_RV::from(CKR_MECHANISM_PARAM_INVALID))?;

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

pub fn resolve_oaep_params(
    parameter: &MechanismParam,
) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, Vec<u8>), CK_RV> {
    let MechanismParam::RsaOaep(oaep) = parameter else {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    };

    if !is_supported_pss_hash(oaep.hash_alg) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mgf_hash = mgf_hash_mechanism(oaep.mgf).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;

    // `source == 0` (unspecified) is treated as an empty label
    let label = match oaep.source {
        0 => Vec::new(),
        s if s == CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE => oaep.source_data.clone(),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };

    Ok((oaep.hash_alg, mgf_hash, label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<T: Copy>(mechanism: u32, value: &T) -> Result<MechanismParam, CK_RV> {
        let mut bytes = vec![0u8; size_of::<T>()];
        // SAFETY: writes exactly `size_of::<T>()` bytes into `bytes`.
        unsafe { std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<T>(), *value) };
        unsafe {
            decode_mechanism_param(
                mechanism as CK_MECHANISM_TYPE,
                bytes.as_ptr(),
                bytes.len() as CK_ULONG,
            )
        }
    }

    #[test]
    fn decodes_oaep_label_into_owned_bytes() {
        let label = b"label".to_vec();
        let params = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
            mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
            source: CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE,
            pSourceData: label.as_ptr() as CK_VOID_PTR,
            ulSourceDataLen: label.len() as CK_ULONG,
        };
        let decoded = decode(CKM_RSA_PKCS_OAEP, &params).unwrap();
        drop(label);
        assert_eq!(
            resolve_oaep_params(&decoded),
            Ok((
                CKM_SHA256 as CK_MECHANISM_TYPE,
                CKM_SHA256 as CK_MECHANISM_TYPE,
                b"label".to_vec()
            ))
        );
    }

    #[test]
    fn decodes_ecdh1_public_data() {
        let peer = vec![0x04u8; 65];
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_EC_KDF_TYPE,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: peer.len() as CK_ULONG,
            pPublicData: peer.as_ptr() as CK_BYTE_PTR,
        };
        assert_eq!(
            decode(CKM_ECDH1_DERIVE, &params),
            Ok(MechanismParam::Ecdh1Derive(Ecdh1DeriveParams {
                kdf: CKD_NULL as CK_EC_KDF_TYPE,
                shared_data: Vec::new(),
                public_data: peer,
            }))
        );
    }

    #[test]
    fn rejects_null_nested_pointer_with_length() {
        let params = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL as CK_EC_KDF_TYPE,
            ulSharedDataLen: 0,
            pSharedData: std::ptr::null_mut(),
            ulPublicDataLen: 65,
            pPublicData: std::ptr::null_mut(),
        };
        assert_eq!(
            decode(CKM_ECDH1_DERIVE, &params),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }

    #[test]
    fn passes_through_malformed_parameters() {
        let raw = [1u8, 2, 3];
        let truncated = unsafe {
            decode_mechanism_param(CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE, raw.as_ptr(), 3)
        }
        .unwrap();
        assert_eq!(truncated, MechanismParam::Bytes(raw.to_vec()));
        assert_eq!(
            resolve_oaep_params(&truncated),
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        );
    }
}
