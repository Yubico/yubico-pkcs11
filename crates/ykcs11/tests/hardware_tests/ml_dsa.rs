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

//! ML-DSA private-key import (`C_CreateObject`) and on-device key
//! generation (`C_GenerateKeyPair`) hardware coverage.

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

// (parameter set, expected CKM_ML_DSA signature length, expected
// CKA_VALUE/public key byte length)
const MLDSA_PARAMETER_SETS: [(u32, usize, usize); 3] = [
    (CKP_ML_DSA_44, 2420, 1312),
    (CKP_ML_DSA_65, 3309, 1952),
    (CKP_ML_DSA_87, 4627, 2592),
];

fn generate_ml_dsa_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    parameter_set: u32,
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_ML_DSA);
    let param_set_bytes = ulong_bytes(parameter_set);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut generated = Vec::new();

    for slot in slots {
        let id_bytes = [*slot];
        let mut private_key_template = [
            attr(CKA_CLASS, &class_priv),
            attr(CKA_KEY_TYPE, &key_type),
            attr(CKA_ID, &id_bytes),
        ];
        let mut public_key_template = [
            attr(CKA_CLASS, &class_pub),
            attr(CKA_ID, &id_bytes),
            attr(CKA_PARAMETER_SET, &param_set_bytes),
        ];

        let mut h_public_key: CK_OBJECT_HANDLE = 0;
        let mut h_private_key: CK_OBJECT_HANDLE = 0;
        let rv = unsafe {
            ykcs11::C_GenerateKeyPair(
                h_session,
                &mut mechanism,
                public_key_template.as_mut_ptr(),
                public_key_template.len() as CK_ULONG,
                private_key_template.as_mut_ptr(),
                private_key_template.len() as CK_ULONG,
                &mut h_public_key,
                &mut h_private_key,
            )
        };
        assert_eq!(
            rv,
            CKR_OK as CK_RV,
            "C_GenerateKeyPair (ML-DSA parameter set {parameter_set}, slot {slot})"
        );
        assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
        assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");
        generated.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    generated
}

fn import_ml_dsa_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    parameter_set: u32,
    seed: &[u8],
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type = ulong_bytes(CKK_ML_DSA);
    let param_set_bytes = ulong_bytes(parameter_set);

    let mut imported = Vec::new();

    for slot in slots {
        let id_bytes = [*slot];
        let mut private_key_template = [
            attr(CKA_CLASS, &class_priv),
            attr(CKA_KEY_TYPE, &key_type),
            attr(CKA_ID, &id_bytes),
            attr(CKA_PARAMETER_SET, &param_set_bytes),
            attr(CKA_SEED, seed),
        ];
        let mut h_private_key: CK_OBJECT_HANDLE = 0;
        let rv = unsafe {
            ykcs11::C_CreateObject(
                h_session,
                private_key_template.as_mut_ptr(),
                private_key_template.len() as CK_ULONG,
                &mut h_private_key,
            )
        };
        assert_eq!(
            rv,
            CKR_OK as CK_RV,
            "C_CreateObject (ML-DSA parameter set {parameter_set}, slot {slot})"
        );
        assert_ne!(h_private_key, 0, "C_CreateObject (private key) returned a null handle");

        // Unlike the RSA/EC/Ed25519/X25519 import helpers, no certificate
        // is needed for the public key to appear: firmware >= 6.0 (already
        // required for ML-DSA) always supports INS_GET_METADATA, so
        // objects.rs's read_slot_objects derives the public key straight
        // from the device's response regardless of whether the key was
        // generated on-device or imported.
        let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, *slot, "imported ML-DSA public key");

        imported.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    imported
}

fn mldsa_sign(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE, pubkey: CK_OBJECT_HANDLE, signature_len: usize) {
    login_user(session, CKR_OK as CK_RV);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let rv = unsafe { ykcs11::C_SignInit(session, &mut mechanism, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_SignInit");

    // A private-key operation needs CKU_CONTEXT_SPECIFIC re-login immediately before C_Sign
    login_context_specific(session, CKR_OK as CK_RV);

    let data = vec![0x5au8; 32];
    let mut signature = vec![0u8; signature_len];
    let mut signature_len_out = signature.len() as CK_ULONG;
    let rv = unsafe {
        ykcs11::C_Sign(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len_out,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Sign");
    assert_eq!(signature_len_out as usize, signature.len(), "unexpected ML-DSA signature length");

    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Verify");

    logout(session, CKR_OK as CK_RV);
}

/// FIPS 204's external-mu message representative:
/// `mu = SHAKE256(SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx || message, 64)`
fn ml_dsa_mu(public_key: &[u8], context: &[u8], message: &[u8]) -> [u8; 64] {
    use shake::digest::{ExtendableOutput, Update, XofReader};

    assert!(context.len() <= 255, "ML-DSA context must be at most 255 bytes");

    let mut tr_hasher = shake::Shake256::default();
    tr_hasher.update(public_key);
    let mut tr = [0u8; 64];
    tr_hasher.finalize_xof().read(&mut tr);

    let mut mu_hasher = shake::Shake256::default();
    mu_hasher.update(&tr);
    mu_hasher.update(&[0u8, context.len() as u8]);
    mu_hasher.update(context);
    mu_hasher.update(message);
    let mut mu = [0u8; 64];
    mu_hasher.finalize_xof().read(&mut mu);
    mu
}

/// Signs via `CKM_ML_DSA_EXTERNAL_MU` and checks the resulting signature two
/// ways: indirectly, via the standard context-aware `CKM_ML_DSA` verify over
/// the original message and context (proving the external-mu path produces
/// exactly the signature FIPS 204's ExternalMu-ML-DSA.Sign promises); and
/// directly, via `CKM_ML_DSA_EXTERNAL_MU`'s own verify over `mu` itself.
fn mldsa_sign_external_mu(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    pubkey: CK_OBJECT_HANDLE,
    value_len: usize,
    signature_len: usize,
) {
    login_user(session, CKR_OK as CK_RV);

    let public_key = get_attribute(session, pubkey, CKA_VALUE, value_len, "CKA_VALUE");
    let message = vec![0xa5u8; 300];
    let context = b"ykcs11 hardware test context".to_vec();
    let mu = ml_dsa_mu(&public_key, &context, &message);

    let mut sign_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_EXTERNAL_MU as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let rv = unsafe { ykcs11::C_SignInit(session, &mut sign_mechanism, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_SignInit (external mu)");

    // A private-key operation needs CKU_CONTEXT_SPECIFIC re-login immediately before C_Sign
    login_context_specific(session, CKR_OK as CK_RV);

    let mut signature = vec![0u8; signature_len];
    let mut signature_len_out = signature.len() as CK_ULONG;
    let rv = unsafe {
        ykcs11::C_Sign(
            session,
            mu.as_ptr() as CK_BYTE_PTR,
            mu.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len_out,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Sign (external mu)");
    assert_eq!(signature_len_out as usize, signature.len(), "unexpected external-mu signature length");

    // --- Verify indirectly, via context-aware CKM_ML_DSA over the original
    // message and context ---
    let context_param = CK_SIGN_ADDITIONAL_CONTEXT {
        hedgeVariant: CKH_HEDGE_PREFERRED as CK_HEDGE_TYPE,
        pContext: context.as_ptr() as CK_BYTE_PTR,
        ulContextLen: context.len() as CK_ULONG,
    };
    let mut verify_with_context_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA as CK_MECHANISM_TYPE,
        pParameter: &context_param as *const CK_SIGN_ADDITIONAL_CONTEXT as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() as CK_ULONG,
    };
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_with_context_mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (indirect, CKM_ML_DSA)");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            message.as_ptr() as CK_BYTE_PTR,
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Verify (indirect, CKM_ML_DSA, over the original message+context)");

    // --- Verify directly, via CKM_ML_DSA_EXTERNAL_MU over mu itself ---
    let mut verify_mu_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_EXTERNAL_MU as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_mu_mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (direct, CKM_ML_DSA_EXTERNAL_MU)");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            mu.as_ptr() as CK_BYTE_PTR,
            mu.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Verify (direct, CKM_ML_DSA_EXTERNAL_MU, over mu)");

    // --- Negative: direct verification against the wrong mu must fail ---
    let wrong_mu = ml_dsa_mu(&public_key, &context, b"a different message entirely");
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_mu_mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (wrong mu)");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            wrong_mu.as_ptr() as CK_BYTE_PTR,
            wrong_mu.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_SIGNATURE_INVALID as CK_RV, "C_Verify unexpectedly accepted the wrong mu");

    // --- Negative: direct verification of a tampered signature must fail ---
    let mut tampered_signature = signature.clone();
    tampered_signature[0] ^= 0x01;
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_mu_mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (tampered signature)");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            mu.as_ptr() as CK_BYTE_PTR,
            mu.len() as CK_ULONG,
            tampered_signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_SIGNATURE_INVALID as CK_RV, "C_Verify unexpectedly accepted a tampered signature");

    // --- Negative: direct verification with a wrong-length mu must fail
    // client-side, mirroring verify.rs's own length check ---
    let short_mu = &mu[..32];
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_mu_mechanism, pubkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (short mu)");
    let rv = unsafe {
        ykcs11::C_Verify(
            session,
            short_mu.as_ptr() as CK_BYTE_PTR,
            short_mu.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature_len_out,
        )
    };
    assert_eq!(rv, CKR_DATA_LEN_RANGE as CK_RV, "C_Verify unexpectedly accepted a wrong-length mu");

    // --- Negative: C_VerifyInit with a non-empty context must be rejected --
    // the spec requires ulContextLen == 0 for CKM_ML_DSA_EXTERNAL_MU, same as
    // on the signing side ---
    let mut verify_mu_with_context_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_DSA_EXTERNAL_MU as CK_MECHANISM_TYPE,
        pParameter: &context_param as *const CK_SIGN_ADDITIONAL_CONTEXT as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() as CK_ULONG,
    };
    let rv = unsafe { ykcs11::C_VerifyInit(session, &mut verify_mu_with_context_mechanism, pubkey) };
    assert_eq!(
        rv, CKR_MECHANISM_PARAM_INVALID as CK_RV,
        "C_VerifyInit unexpectedly accepted a non-empty context for CKM_ML_DSA_EXTERNAL_MU"
    );

    // --- Negative: signing a wrong-length mu must fail client-side ---
    let rv = unsafe { ykcs11::C_SignInit(session, &mut sign_mechanism, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_SignInit (short mu)");
    login_context_specific(session, CKR_OK as CK_RV);
    let mut short_sig = vec![0u8; signature_len];
    let mut short_sig_len = short_sig.len() as CK_ULONG;
    let rv = unsafe {
        ykcs11::C_Sign(
            session,
            short_mu.as_ptr() as CK_BYTE_PTR,
            short_mu.len() as CK_ULONG,
            short_sig.as_mut_ptr(),
            &mut short_sig_len,
        )
    };
    assert_eq!(rv, CKR_DATA_LEN_RANGE as CK_RV, "C_Sign unexpectedly accepted a wrong-length mu");

    logout(session, CKR_OK as CK_RV);
}

fn assert_mldsa_pubkey_attributes(
    session: CK_SESSION_HANDLE,
    pubkey: CK_OBJECT_HANDLE,
    parameter_set: u32,
    value_len: usize,
    expected_local: bool,
    label: &str,
) {
    let class = get_attribute(session, pubkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PUBLIC_KEY), "CKA_CLASS");

    let token = get_attribute(session, pubkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, pubkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![0u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, pubkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_ML_DSA), "CKA_KEY_TYPE");

    let local = get_attribute(session, pubkey, CKA_LOCAL, 1, "CKA_LOCAL");
    assert_eq!(local, vec![expected_local as u8], "CKA_LOCAL");

    let encrypt = get_attribute(session, pubkey, CKA_ENCRYPT, 1, "CKA_ENCRYPT");
    assert_eq!(encrypt, vec![1u8], "CKA_ENCRYPT");

    let verify = get_attribute(session, pubkey, CKA_VERIFY, 1, "CKA_VERIFY");
    assert_eq!(verify, vec![1u8], "CKA_VERIFY");

    let derive = get_attribute(session, pubkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![0u8], "CKA_DERIVE");

    let modifiable = get_attribute(session, pubkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let param_set = get_attribute(session, pubkey, CKA_PARAMETER_SET, std::mem::size_of::<CK_ULONG>(), "CKA_PARAMETER_SET");
    assert_eq!(param_set, ulong_bytes(parameter_set), "CKA_PARAMETER_SET");

    let value = get_attribute(session, pubkey, CKA_VALUE, value_len, "CKA_VALUE");
    assert_eq!(value.len(), value_len, "CKA_VALUE length");

    let got_label = get_attribute(session, pubkey, CKA_LABEL, label.len(), "CKA_LABEL");
    assert_eq!(got_label, label.as_bytes(), "CKA_LABEL");
}

fn assert_mldsa_privkey_attributes(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    parameter_set: u32,
    expected_local: bool,
    expected_always_auth: bool,
    label: &str,
) {
    login_user(session, CKR_OK as CK_RV);

    let class = get_attribute(session, privkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PRIVATE_KEY), "CKA_CLASS");

    let token = get_attribute(session, privkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, privkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![1u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, privkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_ML_DSA), "CKA_KEY_TYPE");

    let sensitive = get_attribute(session, privkey, CKA_SENSITIVE, 1, "CKA_SENSITIVE");
    assert_eq!(sensitive, vec![1u8], "CKA_SENSITIVE");

    let always_sensitive = get_attribute(session, privkey, CKA_ALWAYS_SENSITIVE, 1, "CKA_ALWAYS_SENSITIVE");
    assert_eq!(always_sensitive, vec![1u8], "CKA_ALWAYS_SENSITIVE");

    let extractable = get_attribute(session, privkey, CKA_EXTRACTABLE, 1, "CKA_EXTRACTABLE");
    assert_eq!(extractable, vec![0u8], "CKA_EXTRACTABLE");

    let never_extractable = get_attribute(session, privkey, CKA_NEVER_EXTRACTABLE, 1, "CKA_NEVER_EXTRACTABLE");
    assert_eq!(never_extractable, vec![1u8], "CKA_NEVER_EXTRACTABLE");

    let local = get_attribute(session, privkey, CKA_LOCAL, 1, "CKA_LOCAL");
    assert_eq!(local, vec![expected_local as u8], "CKA_LOCAL");

    let sign = get_attribute(session, privkey, CKA_SIGN, 1, "CKA_SIGN");
    assert_eq!(sign, vec![1u8], "CKA_SIGN");

    let derive = get_attribute(session, privkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![0u8], "CKA_DERIVE");

    let always_auth = get_attribute(session, privkey, CKA_ALWAYS_AUTHENTICATE, 1, "CKA_ALWAYS_AUTHENTICATE");
    assert_eq!(always_auth, vec![expected_always_auth as u8], "CKA_ALWAYS_AUTHENTICATE");

    let modifiable = get_attribute(session, privkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let param_set = get_attribute(session, privkey, CKA_PARAMETER_SET, std::mem::size_of::<CK_ULONG>(), "CKA_PARAMETER_SET");
    assert_eq!(param_set, ulong_bytes(parameter_set), "CKA_PARAMETER_SET");

    let got_label = get_attribute(session, privkey, CKA_LABEL, label.len(), "CKA_LABEL");
    assert_eq!(got_label, label.as_bytes(), "CKA_LABEL");

    logout(session, CKR_OK as CK_RV);
}

#[test]
fn test_generated_mldsa() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generated_mldsa: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();

    // ML-DSA needs firmware >= 6.0, which already implies extended-slot
    // support (firmware >= 5.0), so SLOT_LIST_EXTENDED is always safe here.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 6, 0) {
        eprintln!(
            "skipping test_generated_mldsa: firmware {}.{} is older than the 6.0 ML-DSA requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let session = open_session(slot_id);

    for (parameter_set, signature_len, value_len) in MLDSA_PARAMETER_SETS {
        let keys = generate_ml_dsa_keys(session, SLOT_LIST_EXTENDED, parameter_set);

        let (privkey, pubkey) = keys[0];
        assert_mldsa_pubkey_attributes(
            session,
            pubkey,
            parameter_set,
            value_len,
            true,
            "Public key for PIV Authentication",
        );
        assert_mldsa_privkey_attributes(
            session,
            privkey,
            parameter_set,
            true,
            false,
            "Private key for PIV Authentication",
        );

        for (privkey, pubkey) in keys {
            mldsa_sign(session, privkey, pubkey, signature_len);
            mldsa_sign_external_mu(session, privkey, pubkey, value_len, signature_len);
        }
    }

    close_session(session);
}

#[test]
fn test_imported_mldsa() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_imported_mldsa: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();

    // ML-DSA needs firmware >= 6.0, which already implies extended-slot
    // support (firmware >= 5.0), so SLOT_LIST_EXTENDED is always safe here.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 6, 0) {
        eprintln!(
            "skipping test_imported_mldsa: firmware {}.{} is older than the 6.0 ML-DSA requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let session = open_session(slot_id);

    // Hardcoded, arbitrary seed material. FIPS 204 doesn't require
    // anything special of the seed itself, any correctly-sized byte string
    // is a valid key seed, so there's no need to generate real randomness
    // for an import test.
    let seed = [0x42u8; 32];

    for (parameter_set, signature_len, value_len) in MLDSA_PARAMETER_SETS {
        let keys = import_ml_dsa_keys(session, SLOT_LIST_EXTENDED, parameter_set, &seed);

        let (privkey, pubkey) = keys[0];
        assert_mldsa_pubkey_attributes(
            session,
            pubkey,
            parameter_set,
            value_len,
            false,
            "Public key for PIV Authentication",
        );
        assert_mldsa_privkey_attributes(
            session,
            privkey,
            parameter_set,
            false,
            false,
            "Private key for PIV Authentication",
        );

        for (privkey, pubkey) in keys {
            mldsa_sign(session, privkey, pubkey, signature_len);
            mldsa_sign_external_mu(session, privkey, pubkey, value_len, signature_len);
        }
    }

    close_session(session);
}
