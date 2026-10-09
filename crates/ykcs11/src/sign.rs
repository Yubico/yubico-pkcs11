// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! `C_SignInit`/`C_SignUpdate`/`C_SignFinal` backend logic for the YubiKey
//! PIV module. Covers every mechanism `sign_mechanism_init` supports,
//! including the `CKM_RSA_PKCS_PSS`/`CKM_SHAx_RSA_PKCS_PSS` family
//! (mechanisms.c:150-179).
//!
//! The actual RSA/EC/EdDSA private-key operation always happens on the
//! device (`ActivePivSession::sign`, matching `ykpiv_sign_data`) — this
//! module's own job is everything that happens around that call:
//! - picking the right hash (or none at all, for the "raw"/pre-hashed
//!   mechanisms — the caller supplies already-hashed or already-encoded
//!   data directly);
//! - PKCS#1 v1.5 padding the result for RSA, left-zero-padding it for
//!   `CKM_RSA_X_509`, or RSASSA-PSS-encoding it (MGF1 mask, random salt,
//!   RFC 8017 §9.1.1) for the PSS family — the device does a raw modular
//!   exponentiation in every RSA case, not any of the actual signature
//!   padding/encoding itself;
//! - converting the device's DER-encoded ECDSA signature back to the
//!   fixed-width `r || s` format PKCS#11 expects (EdDSA signatures are
//!   already fixed-width on the wire, so no equivalent step is needed
//!   there).

use crate::backend::{PivBackend, piv_error_to_rv};
use pkcs11_common::backend::Slot;
use pkcs11_common::digest::DigestOp;
use pkcs11_common::mechanism::{MechanismKind, classify_mechanism, resolve_pss_params};
use pkcs11_common::session::LoginState;
use pkcs11_common::sign::{digest_info_prefix, emsa_pss_encode, pkcs1_v15_pad, zero_pad};
use pkcs11_sys::*;
use yubikit::keys::{EcCurve, PublicKey, RsaKeySize};
use yubikit::piv::{KeyType, Slot as PivSlot};

/// Everything needed to finish a signing operation once `C_SignFinal` (or
/// `C_Sign`'s equivalent single-shot update+final) is called — stashed in
/// `PivBackend::SessionData` by `sign_init`, opaque to the shared engine.
pub struct SignState {
    slot: PivSlot,
    key_type: KeyType,
    algo: SignAlgorithm,
    acc: Accumulator,
}

/// Where `C_SignUpdate` data goes before it reaches the device — a real
/// hash for the mechanisms with a built-in digest step, or just the raw
/// bytes as given for the "raw"/pre-hashed mechanisms (matches
/// `digest_mechanism_update`'s own `if(md_ctx) hash else buffer raw`
/// branch, mechanisms.c:647-662 — `md_ctx` is only ever set for the 8
/// hash-combined mechanisms in `sign_mechanism_init`).
pub(crate) enum Accumulator {
    Hash(DigestOp),
    Raw(Vec<u8>),
}

impl Accumulator {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Accumulator::Hash(h) => h.update(data),
            Accumulator::Raw(buf) => buf.extend_from_slice(data),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Accumulator::Hash(h) => h.finalize(),
            Accumulator::Raw(buf) => buf,
        }
    }
}

enum SignAlgorithm {
    /// `CKM_RSA_X_509` — no PKCS#1 structure at all, just left-zero-pad
    /// whatever bytes were accumulated out to `modulus_len`.
    RsaX509 { modulus_len: usize },
    /// `CKM_RSA_PKCS` (raw, `hash_mechanism: None` — the accumulated bytes
    /// are PKCS#1-padded directly, with no `DigestInfo` wrapping added) or
    /// one of the `CKM_SHAx_RSA_PKCS` combined mechanisms (`Some`, needs
    /// `DigestInfo`-wrapping the hash before padding). `modulus_len` is the
    /// target padded size either way.
    RsaPkcs1 {
        hash_mechanism: Option<CK_MECHANISM_TYPE>,
        modulus_len: usize,
    },
    /// Byte width of one coordinate (32 for P-256, 48 for P-384) — the
    /// device's DER-encoded `r`/`s` are each padded out to this length.
    /// Covers both `CKM_ECDSA` (raw) and `CKM_ECDSA_SHAx` (hashed) — the
    /// device call and DER-stripping step are identical either way.
    Ecdsa { curve_byte_len: usize },
    /// `CKM_RSA_PKCS_PSS` (raw) or one of the `CKM_SHAx_RSA_PKCS_PSS`
    /// combined mechanisms — covers both the same way `RsaPkcs1` does
    /// (`Accumulator` already holds either the real hash or the caller's
    /// pre-hashed bytes by the time `sign_final` runs); the PSS parameters
    /// themselves (`hashAlg`/`mgf`/`sLen`) came from the mechanism's
    /// `pParameter` at `sign_init` time either way, since PSS always
    /// requires them regardless of whether the mechanism is raw or
    /// combined (mechanisms.c:150-179).
    RsaPss {
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        salt_len: usize,
        modulus_len: usize,
        modulus_bits: usize,
    },
    /// `CKM_EDDSA` — PureEdDSA signs the whole accumulated message directly
    /// (no hash, no padding); the device returns a fixed 64-byte signature
    /// as-is (objects.c:666's DER-stripping `switch` has no case for
    /// `YKPIV_ALGO_ED25519`, unlike the EC algorithms).
    Eddsa,
}

fn rsa_key_type(size: RsaKeySize) -> Result<KeyType, CK_RV> {
    Ok(match size {
        RsaKeySize::Rsa1024 => KeyType::Rsa1024,
        RsaKeySize::Rsa2048 => KeyType::Rsa2048,
        RsaKeySize::Rsa3072 => KeyType::Rsa3072,
        RsaKeySize::Rsa4096 => KeyType::Rsa4096,
        // RsaKeySize is #[non_exhaustive] upstream; PIV only ever reports
        // one of the four variants above today.
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

fn ec_key_type(curve: EcCurve) -> Result<(KeyType, usize), CK_RV> {
    Ok(match curve {
        EcCurve::P256 => (KeyType::EccP256, 32),
        EcCurve::P384 => (KeyType::EccP384, 48),
        // PIV only ever generates P-256/P-384 EC keys; any other curve here
        // would mean the key was imported/discovered oddly.
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

pub fn sign_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<CK_ULONG, CK_RV> {
    let Some((piv_slot, public_key)) =
        crate::objects::find_signing_key(&slot.data.objects, key_handle)
    else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    // Matches ykcs11.c's own re-check in C_SignInit, right after key-handle
    // validation and before mechanism setup (ykcs11.c:2886-2891): "This
    // allows signing when logged in as SO and then doing a context-specific
    // login to sign" — the condition it actually guards is just "someone is
    // logged in at all".
    if slot.login_state == LoginState::Public {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }

    let Some(mech_kind) = classify_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    // Unlike the C reference (whose `default:` mechanism-switch case only
    // ever checks "is this an RSA key", regardless of whether the mechanism
    // is actually ECDSA- or EdDSA-shaped — mechanisms.c:181-186 — and then
    // silently signs with whatever algorithm the *key* turns out to be),
    // this requires the mechanism and key family to actually agree.
    // Stricter than ykcs11.c in this one narrow edge case (mismatched
    // mechanism/key-family pairs that no correctly-written caller would
    // ever hit), never looser.
    let (key_type, algo, out_len) = match (&mech_kind, public_key) {
        (MechanismKind::RsaX509, PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaX509 { modulus_len },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPkcs1Raw, PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPkcs1 {
                    hash_mechanism: None,
                    modulus_len,
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPkcs1Hashed(hash_mechanism), PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPkcs1 {
                    hash_mechanism: Some(*hash_mechanism),
                    modulus_len,
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPssRaw, PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) =
                resolve_pss_params(parameter, None)?;
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPss {
                    hash_mechanism,
                    mgf_hash_mechanism,
                    salt_len,
                    modulus_len,
                    modulus_bits: k.key_size.bit_len(),
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPssHashed(outer_hash), PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) =
                resolve_pss_params(parameter, Some(*outer_hash))?;
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPss {
                    hash_mechanism,
                    mgf_hash_mechanism,
                    salt_len,
                    modulus_len,
                    modulus_bits: k.key_size.bit_len(),
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::EcdsaRaw | MechanismKind::EcdsaHashed(_), PublicKey::Ec(k)) => {
            let (key_type, curve_byte_len) = ec_key_type(k.curve.clone())?;
            (
                key_type,
                SignAlgorithm::Ecdsa { curve_byte_len },
                (curve_byte_len * 2) as CK_ULONG,
            )
        }
        (MechanismKind::Eddsa, PublicKey::Ed25519(_)) => {
            (KeyType::Ed25519, SignAlgorithm::Eddsa, 64)
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };

    let acc = match mech_kind {
        MechanismKind::RsaPkcs1Hashed(h)
        | MechanismKind::EcdsaHashed(h)
        | MechanismKind::RsaPssHashed(h) => Accumulator::Hash(
            DigestOp::new(h).map_err(|_| CK_RV::from(CKR_MECHANISM_INVALID))?,
        ),
        MechanismKind::RsaX509
        | MechanismKind::RsaPkcs1Raw
        | MechanismKind::RsaPssRaw
        | MechanismKind::EcdsaRaw
        | MechanismKind::Eddsa => Accumulator::Raw(Vec::new()),
    };

    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    session.data.sign = Some(SignState {
        slot: piv_slot,
        key_type,
        algo,
        acc,
    });

    Ok(out_len)
}

pub fn sign_update(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    data: &[u8],
) -> Result<(), CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .sign
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.acc.update(data);
    Ok(())
}

pub fn sign_final(slot: &mut Slot<PivBackend>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .sign
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    let message = state.acc.finalize();
    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    match state.algo {
        SignAlgorithm::RsaX509 { modulus_len } => {
            // Matches `RSA_padding_add_none` (mechanisms.c:251-254) — no
            // PKCS#1 structure, just left-zero-padding.
            let padded = zero_pad(&message, modulus_len)?;
            piv.sign(state.slot, state.key_type, &padded)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::RsaPkcs1 {
            hash_mechanism,
            modulus_len,
        } => {
            // Matches sign_mechanism_final's `prepare_rsa_signature` (wrap
            // the digest in a PKCS#1 DigestInfo, only when a hash was
            // actually computed) followed by `RSA_padding_add_PKCS1_type_1`
            // (mechanisms.c:218-230) — both done host-side, since the
            // device only performs the raw RSA private-key operation on
            // whatever fully-padded block it's given.
            let to_pad = match hash_mechanism {
                Some(h) => {
                    let prefix =
                        digest_info_prefix(h).ok_or(CK_RV::from(CKR_MECHANISM_INVALID))?;
                    let mut v = Vec::with_capacity(prefix.len() + message.len());
                    v.extend_from_slice(prefix);
                    v.extend_from_slice(&message);
                    v
                }
                // Raw CKM_RSA_PKCS: whatever the caller handed in goes
                // straight into PKCS#1 padding, with no DigestInfo wrapping
                // added on top — the caller is responsible for that if they
                // want it.
                None => message,
            };
            let padded = pkcs1_v15_pad(&to_pad, modulus_len)?;

            piv.sign(state.slot, state.key_type, &padded)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::RsaPss {
            hash_mechanism,
            mgf_hash_mechanism,
            salt_len,
            modulus_len,
            modulus_bits,
        } => {
            // Matches `RSA_padding_add_PKCS1_PSS_mgf1` (mechanisms.c:224-
            // 226): random salt (RFC 8017 §9.1.1 step 3 — OpenSSL draws it
            // from its own RNG internally; `getrandom` is this module's
            // equivalent OS-backed source, same as `C_GenerateRandom`'s),
            // then the actual EMSA-PSS-ENCODE. `message` here is `mHash` —
            // either the hash this function just computed (combined
            // mechanisms) or whatever pre-hashed bytes the caller supplied
            // directly (raw `CKM_RSA_PKCS_PSS`).
            let mut salt = vec![0u8; salt_len];
            getrandom::fill(&mut salt).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
            let em = emsa_pss_encode(
                &message,
                &salt,
                modulus_bits - 1,
                hash_mechanism,
                mgf_hash_mechanism,
            )?;

            piv.sign(state.slot, state.key_type, &em)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::Ecdsa { curve_byte_len } => {
            // The device signs the accumulated bytes directly for ECDSA —
            // no DigestInfo wrapping (that's an RSA PKCS#1 concept) —
            // matching sign_mechanism_final's padding `switch` having no
            // case at all for ECDSA (padding stays 0, buf/buf_len pass
            // through unmodified from the digest step, or straight from the
            // caller for raw CKM_ECDSA; mechanisms.c:232-257). But a hash
            // longer than the curve's field width (e.g. SHA-384's 48 bytes
            // against P-256's 32-byte field) must be left-truncated to
            // `curve_byte_len` first — `yubikit::piv::sign()` is a dumb
            // passthrough (its own doc comment says `message` must already
            // be "pre-padded/pre-hashed data appropriate for the key type"),
            // so this doesn't happen for free the way it does in the C
            // reference, where libykpiv's `_general_authenticate` applies
            // this exact clamp just before building the APDU
            // (lib/ykpiv.c:1764-1777) — matching ECDSA's own
            // leftmost-bits-of-the-hash rule (SEC1/ANSI X9.62) for when the
            // digest is longer than the curve order.
            let truncated = if message.len() > curve_byte_len {
                &message[..curve_byte_len]
            } else {
                &message[..]
            };
            let der_sig = piv
                .sign(state.slot, state.key_type, truncated)
                .map_err(piv_error_to_rv)?;
            strip_ecdsa_der(&der_sig, curve_byte_len)
        }
        SignAlgorithm::Eddsa => piv
            .sign(state.slot, state.key_type, &message)
            .map_err(piv_error_to_rv),
    }
}

/// Converts the device's DER-encoded ECDSA signature into PKCS#11's
/// fixed-width `r || s` format — matches `do_strip_DER_encoding_from_ECSIG`
/// (openssl_utils.c:638-663), which does the same `BN_bn2binpad`-style
/// left-padding via OpenSSL instead. `ecdsa::Signature::from_der` (exposed
/// through `p256`/`p384`, the same curve crates `yubikit` itself already
/// depends on) already left-zero-pads each coordinate to the curve's fixed
/// field width and validates `r`/`s` are in range, so no hand-rolled DER
/// parsing is needed here.
fn strip_ecdsa_der(der_sig: &[u8], curve_byte_len: usize) -> Result<Vec<u8>, CK_RV> {
    match curve_byte_len {
        32 => Ok(p256::ecdsa::Signature::from_der(der_sig)
            .map_err(|_| CK_RV::from(CKR_DATA_INVALID))?
            .to_bytes()
            .to_vec()),
        48 => Ok(p384::ecdsa::Signature::from_der(der_sig)
            .map_err(|_| CK_RV::from(CKR_DATA_INVALID))?
            .to_bytes()
            .to_vec()),
        // ec_key_type only ever produces 32 (P-256) or 48 (P-384).
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hand-built `ECDSA-Sig-Value ::= SEQUENCE { r, s }` where `s` has its
    // high bit set (DER requires an extra leading 0x00 byte for the INTEGER
    // to stay non-negative) and `r` is shorter than the curve's 32-byte
    // coordinate width (requires left-zero-padding on the way out) — the two
    // edge cases a byte-for-byte DER parser is most likely to get wrong.
    const DER_SIG: &[u8] = &[
        0x30, 0x16, 0x02, 0x09, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x02, 0x09,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn strip_ecdsa_der_pads_and_concatenates_r_and_s() {
        let raw = strip_ecdsa_der(DER_SIG, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(
            hex(&raw[..32]),
            "000000000000000000000000000000000000000000000000abcdef0123456789"
        );
        assert_eq!(
            hex(&raw[32..]),
            "000000000000000000000000000000000000000000000000ff00000000000001"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
