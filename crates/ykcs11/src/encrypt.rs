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

use pkcs11_common::backend::Slot;
use pkcs11_common::encrypt::{rsa_oaep_encrypt, rsa_pkcs1_encrypt, rsa_x509_encrypt};
use pkcs11_common::mechanism::{CryptMechanismKind, classify_crypt_mechanism, resolve_oaep_params};
use pkcs11_sys::*;
use yubikit::keys::PublicKey;

use crate::backend::PivBackend;

pub struct EncryptState {
    n: Vec<u8>,
    e: Vec<u8>,
    modulus_len: usize,
    algo: EncryptAlgorithm,
    buf: Vec<u8>,
}

enum EncryptAlgorithm {
    RsaX509,
    RsaPkcs1,
    RsaOaep {
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        label: Vec<u8>,
    },
}

pub fn encrypt_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<CK_ULONG, CK_RV> {
    let Some((_, public_key)) = crate::objects::find_public_key(&slot.data.objects, key_handle) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    let Some(mech_kind) = classify_crypt_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    let PublicKey::Rsa(k) = public_key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    let modulus_len = k.key_size.bit_len() / 8;

    let algo = match mech_kind {
        CryptMechanismKind::RsaX509 => EncryptAlgorithm::RsaX509,
        CryptMechanismKind::RsaPkcs1 => EncryptAlgorithm::RsaPkcs1,
        CryptMechanismKind::RsaOaep => {
            let (hash_mechanism, mgf_hash_mechanism, label) = resolve_oaep_params(parameter)?;
            EncryptAlgorithm::RsaOaep {
                hash_mechanism,
                mgf_hash_mechanism,
                label,
            }
        }
    };

    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    session.data.encrypt = Some(EncryptState {
        n: k.n.clone(),
        e: k.e.clone(),
        modulus_len,
        algo,
        buf: Vec::new(),
    });

    Ok(modulus_len as CK_ULONG)
}

pub fn encrypt_update(
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
        .encrypt
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.buf.extend_from_slice(data);
    Ok(())
}

pub fn encrypt_final(slot: &mut Slot<PivBackend>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .encrypt
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    match state.algo {
        EncryptAlgorithm::RsaX509 => {
            rsa_x509_encrypt(&state.n, &state.e, state.modulus_len, &state.buf)
        }
        EncryptAlgorithm::RsaPkcs1 => {
            let ps_len = state
                .modulus_len
                .checked_sub(state.buf.len() + 3)
                .ok_or(CK_RV::from(CKR_DATA_LEN_RANGE))?;
            let ps = non_zero_random_bytes(ps_len)?;
            rsa_pkcs1_encrypt(&state.n, &state.e, state.modulus_len, &state.buf, &ps)
        }
        EncryptAlgorithm::RsaOaep {
            hash_mechanism,
            mgf_hash_mechanism,
            label,
        } => {
            let h_len = pkcs11_common::digest::DigestOp::new(hash_mechanism)?.output_len();
            let seed = random_bytes(h_len)?;
            rsa_oaep_encrypt(
                &state.n,
                &state.e,
                state.modulus_len,
                &state.buf,
                &label,
                &seed,
                hash_mechanism,
                mgf_hash_mechanism,
            )
        }
    }
}

fn non_zero_random_bytes(len: usize) -> Result<Vec<u8>, CK_RV> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
    for byte in buf.iter_mut() {
        while *byte == 0 {
            getrandom::fill(std::slice::from_mut(byte)).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
        }
    }
    Ok(buf)
}

fn random_bytes(len: usize) -> Result<Vec<u8>, CK_RV> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
    Ok(buf)
}
