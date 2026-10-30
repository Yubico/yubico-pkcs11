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

/// Yubico's vendor-mechanism namespace: `CKM_VENDOR_DEFINED |
/// YUBICO_BASE_VENDOR`, the exact same convention `objects.rs`'s own
/// `CKA_YUBICO`/`CKA_YUBICO_TOUCH_POLICY`/`CKA_YUBICO_PIN_POLICY` already
/// use for vendor *attributes* (mirroring `ykcs11.c`'s own `pkcs11y.h`),
/// just under `CKM_VENDOR_DEFINED` instead of `CKA_VENDOR_DEFINED` since
/// this one is a mechanism. No equivalent exists in the C reference, which
/// defines no vendor mechanisms at all — this one is new, invented here
/// purely for `CKM_YUBICO_ML_DSA_EXTERNAL_MU`'s sake.
const YUBICO_BASE_VENDOR: u32 = 0x59554200;
const CKM_YUBICO: u32 = CKM_VENDOR_DEFINED + YUBICO_BASE_VENDOR;

/// A Yubico vendor-defined mechanism: ML-DSA (FIPS 204) signing over an
/// externally-computed message representative `mu`, instead of the raw
/// message (`yubikit::piv::PivSession::sign_external_mu`, tag `0x88` in the
/// Dynamic Authentication Template — see `sign.rs`'s own doc comment).
/// PKCS#11 has no standard mechanism for this: `CKM_ML_DSA`'s `C_Sign` data
/// argument is defined as the message to be signed, with no way to signal
/// "this is already `mu`, don't touch it", so a distinct mechanism type is
/// the only way to express the difference without overloading `CKM_ML_DSA`'s
/// existing, spec-defined meaning. Not part of the shared, standards-focused
/// `pkcs11_common::mechanism::MechanismKind` enum (unlike `CKM_ML_DSA`
/// itself) — this is a one-off YubiKey PIV vendor extension with no
/// cross-module relevance, so `sign.rs`'s `sign_init` checks for it
/// directly instead. Sign-only: a signature this mechanism produces
/// verifies with the exact same `CKM_ML_DSA` context-aware verify already
/// implemented (`verify.rs`'s `verify_ml_dsa`) against the original message
/// and context `mu` was computed from — there's no corresponding "verify
/// with mu" operation to add, since the verifier never needs the
/// constrained-signer's shortcut.
pub(crate) const CKM_YUBICO_ML_DSA_EXTERNAL_MU: u32 = CKM_YUBICO + 1;

const MIN_RSA_KEY_SIZE: CK_ULONG = 1024;
const MAX_RSA_KEY_SIZE: CK_ULONG = 4096;
const MIN_ECC_KEY_SIZE: CK_ULONG = 256;
const MAX_ECC_KEY_SIZE: CK_ULONG = 384;

pub struct MechanismEntry {
    pub mechanism: CK_MECHANISM_TYPE,
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

pub fn mechanism_table() -> Vec<MechanismEntry> {
    vec![
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_ENCRYPT as CK_FLAGS
                | CKF_DECRYPT as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_PSS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_OAEP.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_ENCRYPT as CK_FLAGS | CKF_DECRYPT as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_X_509.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_ENCRYPT as CK_FLAGS
                | CKF_DECRYPT as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA1_RSA_PKCS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256_RSA_PKCS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384_RSA_PKCS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512_RSA_PKCS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA1_RSA_PKCS_PSS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256_RSA_PKCS_PSS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384_RSA_PKCS_PSS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512_RSA_PKCS_PSS.into(),
            min_key_size: MIN_RSA_KEY_SIZE,
            max_key_size: MAX_RSA_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_EC_KEY_PAIR_GEN.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA1.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA224.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA256.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA384.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA512.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDH1_DERIVE.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_DERIVE as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA_1.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_EDDSA.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ML_DSA_KEY_PAIR_GEN.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ML_KEM_KEY_PAIR_GEN.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ML_KEM.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_ENCAPSULATE as CK_FLAGS | CKF_DECAPSULATE as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ML_DSA.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        // Yubico vendor mechanism -- see `CKM_YUBICO_ML_DSA_EXTERNAL_MU`'s
        // own doc comment above for why `CKM_ML_DSA` itself can't express
        // this. `CKF_SIGN` only, no `CKF_VERIFY` (same doc comment); same
        // "no bit-length key size concept" as the other ML-DSA/ML-KEM
        // entries.
        MechanismEntry {
            mechanism: CKM_YUBICO_ML_DSA_EXTERNAL_MU.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS,
        },
    ]
}

pub fn token_mechanisms() -> Vec<CK_MECHANISM_TYPE> {
    mechanism_table().into_iter().map(|e| e.mechanism).collect()
}
