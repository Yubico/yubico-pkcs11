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


//! Maps the connected device's reported algorithm capabilities to the
//! `CKM_*` mechanisms `C_GetMechanismList` should report — dynamic, unlike
//! ykcs11's fixed table, matching `get_mechanism_list` in the original C
//! module's `util_pkcs11.c`, which builds the list from
//! `slot->connector->device_info.algorithms[]`.

use pkcs11_sys::*;
use yubihsmrs::object::ObjectAlgorithm;

/// Yubico HSM vendor mechanisms. Not in the OASIS headers our `pkcs11-sys`
/// vendors — they're defined in yubihsm-shell's own `pkcs11y.h`, and their
/// values depend on yubihsm-shell's own libyubihsm object-type constants
/// (`YH_WRAP_KEY`/`YH_PUBLIC_WRAP_KEY`), which have nothing to do with the
/// PKCS#11 spec itself, so they don't belong in the shared crate. Values
/// computed the same way as that header:
/// `CKM_VENDOR_DEFINED (0x80000000) | YUBICO_BASE_VENDOR (0x59554200) | <YH object type>`.
const CKM_YUBICO_AES_CCM_WRAP: CK_MECHANISM_TYPE = 0xD9554204; // | YH_WRAP_KEY (0x04)
const CKM_YUBICO_RSA_WRAP: CK_MECHANISM_TYPE = 0xD9554209; // | YH_PUBLIC_WRAP_KEY (0x09)

fn push(list: &mut Vec<CK_MECHANISM_TYPE>, m: CK_MECHANISM_TYPE) {
    if !list.contains(&m) {
        list.push(m);
    }
}

pub struct MechanismInfo {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

/// Min/max RSA key size in *bits* across the device's supported algorithms,
/// matching `find_minmax_rsa_key_length_in_bits` in the C module's
/// `util_pkcs11.c`.
fn minmax_rsa_key_length_in_bits(algorithms: &[ObjectAlgorithm]) -> (CK_ULONG, CK_ULONG) {
    let mut min = 0;
    let mut max = 0;
    for algo in algorithms {
        let size: CK_ULONG = match algo {
            ObjectAlgorithm::Rsa2048 => 2048,
            ObjectAlgorithm::Rsa3072 => 3072,
            ObjectAlgorithm::Rsa4096 => 4096,
            _ => continue,
        };
        if min == 0 || min > size {
            min = size;
        }
        if size > max {
            max = size;
        }
    }
    (min, max)
}

/// Min/max EC key size in *bits*, matching
/// `find_minmax_ec_key_length_in_bits`.
fn minmax_ec_key_length_in_bits(algorithms: &[ObjectAlgorithm]) -> (CK_ULONG, CK_ULONG) {
    let mut min = 0;
    let mut max = 0;
    for algo in algorithms {
        let size: CK_ULONG = match algo {
            ObjectAlgorithm::EcP224 => 224,
            ObjectAlgorithm::EcP256 | ObjectAlgorithm::EcK256 | ObjectAlgorithm::EcBp256 => 256,
            ObjectAlgorithm::EcP384 | ObjectAlgorithm::EcBp384 => 384,
            ObjectAlgorithm::EcBp512 => 512,
            ObjectAlgorithm::EcP521 => 521,
            _ => continue,
        };
        if min == 0 || min > size {
            min = size;
        }
        if size > max {
            max = size;
        }
    }
    (min, max)
}

/// Min/max AES key size in *bytes*, matching
/// `find_minmax_aes_key_length_in_bytes`.
fn minmax_aes_key_length_in_bytes(algorithms: &[ObjectAlgorithm]) -> (CK_ULONG, CK_ULONG) {
    let mut min = 0;
    let mut max = 0;
    for algo in algorithms {
        let size: CK_ULONG = match algo {
            ObjectAlgorithm::Aes128 => 16,
            ObjectAlgorithm::Aes192 => 24,
            ObjectAlgorithm::Aes256 => 32,
            _ => continue,
        };
        if min == 0 || min > size {
            min = size;
        }
        if size > max {
            max = size;
        }
    }
    (min, max)
}

/// Matches `get_mechanism_info` in the C module's `util_pkcs11.c`.
pub fn mechanism_info(algorithms: &[ObjectAlgorithm], mechanism: CK_MECHANISM_TYPE) -> Option<MechanismInfo> {
    let rsa = || minmax_rsa_key_length_in_bits(algorithms);
    let ec = || minmax_ec_key_length_in_bits(algorithms);
    let aes = || minmax_aes_key_length_in_bytes(algorithms);

    let (min_key_size, max_key_size, flags): (CK_ULONG, CK_ULONG, CK_FLAGS) = match mechanism {
        m if m == CKM_RSA_PKCS.into() => {
            let (min, max) = rsa();
            (
                min,
                max,
                CKF_HW as CK_FLAGS
                    | CKF_ENCRYPT as CK_FLAGS
                    | CKF_DECRYPT as CK_FLAGS
                    | CKF_SIGN as CK_FLAGS
                    | CKF_VERIFY as CK_FLAGS,
            )
        }
        m if m == CKM_SHA1_RSA_PKCS.into()
            || m == CKM_SHA256_RSA_PKCS.into()
            || m == CKM_SHA384_RSA_PKCS.into()
            || m == CKM_SHA512_RSA_PKCS.into() =>
        {
            let (min, max) = rsa();
            (min, max, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS)
        }
        m if m == CKM_RSA_PKCS_PSS.into()
            || m == CKM_SHA1_RSA_PKCS_PSS.into()
            || m == CKM_SHA256_RSA_PKCS_PSS.into()
            || m == CKM_SHA384_RSA_PKCS_PSS.into()
            || m == CKM_SHA512_RSA_PKCS_PSS.into() =>
        {
            let (min, max) = rsa();
            (min, max, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS)
        }
        m if m == CKM_RSA_PKCS_OAEP.into() => {
            let (min, max) = rsa();
            (min, max, CKF_HW as CK_FLAGS | CKF_DECRYPT as CK_FLAGS | CKF_ENCRYPT as CK_FLAGS)
        }
        m if m == CKM_YUBICO_RSA_WRAP || m == CKM_RSA_AES_KEY_WRAP.into() => {
            let (min, max) = rsa();
            (min, max, CKF_HW as CK_FLAGS | CKF_WRAP as CK_FLAGS | CKF_UNWRAP as CK_FLAGS)
        }
        m if m == CKM_RSA_PKCS_KEY_PAIR_GEN.into() => {
            let (min, max) = rsa();
            (min, max, CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS)
        }
        m if m == CKM_EC_KEY_PAIR_GEN.into() => {
            let (min, max) = ec();
            (
                min,
                max,
                CKF_HW as CK_FLAGS
                    | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                    | CKF_EC_F_P as CK_FLAGS
                    | CKF_EC_NAMEDCURVE as CK_FLAGS
                    | CKF_EC_UNCOMPRESS as CK_FLAGS,
            )
        }
        m if m == CKM_EC_EDWARDS_KEY_PAIR_GEN.into() => (
            255,
            255,
            CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_COMPRESS as CK_FLAGS,
        ),
        m if m == CKM_EDDSA.into() => (
            255,
            255,
            CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_COMPRESS as CK_FLAGS,
        ),
        m if m == CKM_SHA_1_HMAC.into() => (1, 64 * 8, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS),
        m if m == CKM_SHA256_HMAC.into() => (1, 64 * 8, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS),
        m if m == CKM_SHA384_HMAC.into() => (1, 128 * 8, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS),
        m if m == CKM_SHA512_HMAC.into() => (1, 128 * 8, CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS),
        m if m == CKM_ECDSA.into()
            || m == CKM_ECDSA_SHA1.into()
            || m == CKM_ECDSA_SHA256.into()
            || m == CKM_ECDSA_SHA384.into()
            || m == CKM_ECDSA_SHA512.into() =>
        {
            let (min, max) = ec();
            (
                min,
                max,
                CKF_HW as CK_FLAGS
                    | CKF_SIGN as CK_FLAGS
                    | CKF_VERIFY as CK_FLAGS
                    | CKF_EC_F_P as CK_FLAGS
                    | CKF_EC_NAMEDCURVE as CK_FLAGS
                    | CKF_EC_UNCOMPRESS as CK_FLAGS,
            )
        }
        m if m == CKM_ECDH1_DERIVE.into() => {
            let (min, max) = ec();
            (
                min,
                max,
                CKF_HW as CK_FLAGS
                    | CKF_DERIVE as CK_FLAGS
                    | CKF_EC_F_P as CK_FLAGS
                    | CKF_EC_NAMEDCURVE as CK_FLAGS
                    | CKF_EC_UNCOMPRESS as CK_FLAGS,
            )
        }
        m if m == CKM_SHA_1.into() || m == CKM_SHA256.into() || m == CKM_SHA384.into() || m == CKM_SHA512.into() => {
            (0, 0, CKF_DIGEST as CK_FLAGS)
        }
        m if m == CKM_YUBICO_AES_CCM_WRAP => (
            128,
            256,
            CKF_HW as CK_FLAGS
                | CKF_WRAP as CK_FLAGS
                | CKF_UNWRAP as CK_FLAGS
                | CKF_ENCRYPT as CK_FLAGS
                | CKF_DECRYPT as CK_FLAGS,
        ),
        m if m == CKM_GENERIC_SECRET_KEY_GEN.into() => (1, 128 * 8, CKF_HW as CK_FLAGS | CKF_GENERATE as CK_FLAGS),
        m if m == CKM_AES_KEY_GEN.into() => {
            let (min, max) = aes();
            (min, max, CKF_HW as CK_FLAGS | CKF_GENERATE as CK_FLAGS)
        }
        m if m == CKM_AES_ECB.into() || m == CKM_AES_CBC.into() || m == CKM_AES_CBC_PAD.into() => {
            let (min, max) = aes();
            (min, max, CKF_HW as CK_FLAGS | CKF_ENCRYPT as CK_FLAGS | CKF_DECRYPT as CK_FLAGS)
        }
        m if m == CKM_AES_KEY_WRAP_KWP.into() => {
            let (min, max) = aes();
            (min, max, CKF_HW as CK_FLAGS)
        }
        _ => return None,
    };

    Some(MechanismInfo {
        min_key_size,
        max_key_size,
        flags,
    })
}

pub fn mechanism_list(algorithms: &[ObjectAlgorithm]) -> Vec<CK_MECHANISM_TYPE> {
    let mut m: Vec<CK_MECHANISM_TYPE> = Vec::new();

    for algo in algorithms {
        match algo {
            ObjectAlgorithm::RsaPkcs1Sha1 => {
                push(&mut m, CKM_RSA_PKCS.into());
                push(&mut m, CKM_SHA1_RSA_PKCS.into());
            }
            ObjectAlgorithm::RsaPkcs1Sha256 => {
                push(&mut m, CKM_RSA_PKCS.into());
                push(&mut m, CKM_SHA256_RSA_PKCS.into());
            }
            ObjectAlgorithm::RsaPkcs1Sha384 => {
                push(&mut m, CKM_RSA_PKCS.into());
                push(&mut m, CKM_SHA384_RSA_PKCS.into());
            }
            ObjectAlgorithm::RsaPkcs1Sha512 => {
                push(&mut m, CKM_RSA_PKCS.into());
                push(&mut m, CKM_SHA512_RSA_PKCS.into());
            }
            ObjectAlgorithm::RsaPssSha1 => {
                push(&mut m, CKM_RSA_PKCS_PSS.into());
                push(&mut m, CKM_SHA1_RSA_PKCS_PSS.into());
            }
            ObjectAlgorithm::RsaPssSha256 => {
                push(&mut m, CKM_RSA_PKCS_PSS.into());
                push(&mut m, CKM_SHA256_RSA_PKCS_PSS.into());
            }
            ObjectAlgorithm::RsaPssSha384 => {
                push(&mut m, CKM_RSA_PKCS_PSS.into());
                push(&mut m, CKM_SHA384_RSA_PKCS_PSS.into());
            }
            ObjectAlgorithm::RsaPssSha512 => {
                push(&mut m, CKM_RSA_PKCS_PSS.into());
                push(&mut m, CKM_SHA512_RSA_PKCS_PSS.into());
            }
            ObjectAlgorithm::Rsa2048 | ObjectAlgorithm::Rsa3072 | ObjectAlgorithm::Rsa4096 => {
                push(&mut m, CKM_RSA_PKCS_KEY_PAIR_GEN.into());
            }
            ObjectAlgorithm::EcP224
            | ObjectAlgorithm::EcP256
            | ObjectAlgorithm::EcP384
            | ObjectAlgorithm::EcP521
            | ObjectAlgorithm::EcK256
            | ObjectAlgorithm::EcBp256
            | ObjectAlgorithm::EcBp384
            | ObjectAlgorithm::EcBp512 => {
                push(&mut m, CKM_EC_KEY_PAIR_GEN.into());
            }
            ObjectAlgorithm::Ed25519 => {
                push(&mut m, CKM_EDDSA.into());
                push(&mut m, CKM_EC_EDWARDS_KEY_PAIR_GEN.into());
            }
            ObjectAlgorithm::HmacSha1 => {
                push(&mut m, CKM_SHA_1_HMAC.into());
                push(&mut m, CKM_GENERIC_SECRET_KEY_GEN.into());
            }
            ObjectAlgorithm::HmacSha256 => {
                push(&mut m, CKM_SHA256_HMAC.into());
                push(&mut m, CKM_GENERIC_SECRET_KEY_GEN.into());
            }
            ObjectAlgorithm::HmacSha384 => {
                push(&mut m, CKM_SHA384_HMAC.into());
                push(&mut m, CKM_GENERIC_SECRET_KEY_GEN.into());
            }
            ObjectAlgorithm::HmacSha512 => {
                push(&mut m, CKM_SHA512_HMAC.into());
                push(&mut m, CKM_GENERIC_SECRET_KEY_GEN.into());
            }
            ObjectAlgorithm::EcdsaSha1 => {
                push(&mut m, CKM_ECDSA.into());
                push(&mut m, CKM_ECDSA_SHA1.into());
            }
            ObjectAlgorithm::EcdsaSha256 => {
                push(&mut m, CKM_ECDSA.into());
                push(&mut m, CKM_ECDSA_SHA256.into());
            }
            ObjectAlgorithm::EcdsaSha384 => {
                push(&mut m, CKM_ECDSA.into());
                push(&mut m, CKM_ECDSA_SHA384.into());
            }
            ObjectAlgorithm::EcdsaSha512 => {
                push(&mut m, CKM_ECDSA.into());
                push(&mut m, CKM_ECDSA_SHA512.into());
            }
            ObjectAlgorithm::Ecdh => {
                push(&mut m, CKM_ECDH1_DERIVE.into());
            }
            ObjectAlgorithm::RsaOaepSha1
            | ObjectAlgorithm::RsaOaepSha256
            | ObjectAlgorithm::RsaOaepSha384
            | ObjectAlgorithm::RsaOaepSha512 => {
                push(&mut m, CKM_RSA_PKCS_OAEP.into());
            }
            ObjectAlgorithm::AesKwp => {
                push(&mut m, CKM_AES_KEY_WRAP_KWP.into());
            }
            ObjectAlgorithm::Aes128CcmWrap
            | ObjectAlgorithm::Aes192CcmWrap
            | ObjectAlgorithm::Aes256CcmWrap => {
                push(&mut m, CKM_YUBICO_AES_CCM_WRAP);
                push(&mut m, CKM_GENERIC_SECRET_KEY_GEN.into());
            }
            ObjectAlgorithm::Aes128 | ObjectAlgorithm::Aes192 | ObjectAlgorithm::Aes256 => {
                push(&mut m, CKM_AES_KEY_GEN.into());
            }
            ObjectAlgorithm::AesEcb => {
                push(&mut m, CKM_AES_ECB.into());
            }
            ObjectAlgorithm::AesCbc => {
                push(&mut m, CKM_AES_CBC.into());
                push(&mut m, CKM_AES_CBC_PAD.into());
            }
            _ => {}
        }
    }

    // CKM_YUBICO_RSA_WRAP/CKM_RSA_AES_KEY_WRAP require both an OAEP variant
    // and AES-KWP support on the device, matching the C module's
    // find_mech() cross-checks in both the OAEP and AES-KWP branches.
    let has_oaep = algorithms.iter().any(|a| {
        matches!(
            a,
            ObjectAlgorithm::RsaOaepSha1
                | ObjectAlgorithm::RsaOaepSha256
                | ObjectAlgorithm::RsaOaepSha384
                | ObjectAlgorithm::RsaOaepSha512
        )
    });
    let has_kwp = algorithms.contains(&ObjectAlgorithm::AesKwp);
    if has_oaep && has_kwp {
        push(&mut m, CKM_YUBICO_RSA_WRAP);
        push(&mut m, CKM_RSA_AES_KEY_WRAP.into());
    }

    // Unconditional in the C module — always reported regardless of device
    // capability.
    push(&mut m, CKM_SHA_1.into());
    push(&mut m, CKM_SHA256.into());
    push(&mut m, CKM_SHA384.into());
    push(&mut m, CKM_SHA512.into());

    m
}
