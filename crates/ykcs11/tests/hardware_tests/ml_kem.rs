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

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

// (parameter set, expected ciphertext length, expected CKA_VALUE/public key
// byte length)
const MLKEM_PARAMETER_SETS: [(u32, usize, usize); 3] = [
    (CKP_ML_KEM_512, 768, 800),
    (CKP_ML_KEM_768, 1088, 1184),
    (CKP_ML_KEM_1024, 1568, 1568),
];

// FIPS 203's shared secret length is fixed at 32 bytes for every parameter set.
const MLKEM_SECRET_LEN: usize = 32;

fn generate_ml_kem_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    parameter_set: u32,
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_ML_KEM);
    let param_set_bytes = ulong_bytes(parameter_set);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
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
            "C_GenerateKeyPair (ML-KEM parameter set {parameter_set}, slot {slot})"
        );
        assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
        assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");
        generated.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    generated
}

fn import_ml_kem_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    parameter_set: u32,
    seed: &[u8],
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type = ulong_bytes(CKK_ML_KEM);
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
            "C_CreateObject (ML-KEM parameter set {parameter_set}, slot {slot})"
        );
        assert_ne!(h_private_key, 0, "C_CreateObject (private key) returned a null handle");

        // Unlike the RSA/EC/Ed25519/X25519 import helpers, no certificate
        // is needed for the public key to appear: firmware >= 6.0 (already
        // required for ML-KEM) always supports INS_GET_METADATA, so
        // objects.rs's read_slot_objects derives the public key straight
        // from the device's response regardless of whether the key was
        // generated on-device or imported.
        let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, *slot, "imported ML-KEM public key");

        imported.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    imported
}

/// Encapsulates a fresh shared secret against `pubkey`, decapsulates the
/// resulting ciphertext with `privkey`, and confirms both sides land on the
/// identical shared secret
fn mlkem_decapsulate(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE, pubkey: CK_OBJECT_HANDLE, ciphertext_len: usize) {
    login_user(session, CKR_OK as CK_RV);

    let mut encap_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_KEM as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut ciphertext = vec![0u8; ciphertext_len];
    let mut ciphertext_len_out = ciphertext.len() as CK_ULONG;
    let mut h_encap_secret: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_EncapsulateKey(
            session,
            &mut encap_mechanism,
            pubkey,
            ptr::null_mut(),
            0,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len_out,
            &mut h_encap_secret,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_EncapsulateKey");
    assert_eq!(ciphertext_len_out as usize, ciphertext.len(), "unexpected ML-KEM ciphertext length");
    assert_ne!(h_encap_secret, 0, "C_EncapsulateKey returned a null handle");

    let encapsulated_secret = get_attribute(session, h_encap_secret, CKA_VALUE, MLKEM_SECRET_LEN, "encapsulated secret");

    let mut decap_mechanism = CK_MECHANISM {
        mechanism: CKM_ML_KEM as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut h_decap_secret: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_DecapsulateKey(
            session,
            &mut decap_mechanism,
            privkey,
            ptr::null_mut(),
            0,
            ciphertext.as_mut_ptr(),
            ciphertext_len_out,
            &mut h_decap_secret,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_DecapsulateKey");
    assert_ne!(h_decap_secret, 0, "C_DecapsulateKey returned a null handle");

    let decapsulated_secret = get_attribute(session, h_decap_secret, CKA_VALUE, MLKEM_SECRET_LEN, "decapsulated secret");

    assert_eq!(
        encapsulated_secret, decapsulated_secret,
        "host-encapsulated and device-decapsulated shared secrets don't match"
    );

    logout(session, CKR_OK as CK_RV);
}

fn assert_mlkem_pubkey_attributes(
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
    assert_eq!(key_type, ulong_bytes(CKK_ML_KEM), "CKA_KEY_TYPE");

    let local = get_attribute(session, pubkey, CKA_LOCAL, 1, "CKA_LOCAL");
    assert_eq!(local, vec![expected_local as u8], "CKA_LOCAL");

    let encrypt = get_attribute(session, pubkey, CKA_ENCRYPT, 1, "CKA_ENCRYPT");
    assert_eq!(encrypt, vec![1u8], "CKA_ENCRYPT");

    let verify = get_attribute(session, pubkey, CKA_VERIFY, 1, "CKA_VERIFY");
    assert_eq!(verify, vec![1u8], "CKA_VERIFY");

    let derive = get_attribute(session, pubkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![0u8], "CKA_DERIVE");

    let encapsulate = get_attribute(session, pubkey, CKA_ENCAPSULATE, 1, "CKA_ENCAPSULATE");
    assert_eq!(encapsulate, vec![1u8], "CKA_ENCAPSULATE");

    let modifiable = get_attribute(session, pubkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let param_set = get_attribute(session, pubkey, CKA_PARAMETER_SET, std::mem::size_of::<CK_ULONG>(), "CKA_PARAMETER_SET");
    assert_eq!(param_set, ulong_bytes(parameter_set), "CKA_PARAMETER_SET");

    let value = get_attribute(session, pubkey, CKA_VALUE, value_len, "CKA_VALUE");
    assert_eq!(value.len(), value_len, "CKA_VALUE length");

    let got_label = get_attribute(session, pubkey, CKA_LABEL, label.len(), "CKA_LABEL");
    assert_eq!(got_label, label.as_bytes(), "CKA_LABEL");
}

fn assert_mlkem_privkey_attributes(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    parameter_set: u32,
    expected_local: bool,
    expected_always_auth: bool,
    label: &str,
) {
    let class = get_attribute(session, privkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PRIVATE_KEY), "CKA_CLASS");

    let token = get_attribute(session, privkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, privkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![1u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, privkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_ML_KEM), "CKA_KEY_TYPE");

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

    let decapsulate = get_attribute(session, privkey, CKA_DECAPSULATE, 1, "CKA_DECAPSULATE");
    assert_eq!(decapsulate, vec![1u8], "CKA_DECAPSULATE");

    let always_auth = get_attribute(session, privkey, CKA_ALWAYS_AUTHENTICATE, 1, "CKA_ALWAYS_AUTHENTICATE");
    assert_eq!(always_auth, vec![expected_always_auth as u8], "CKA_ALWAYS_AUTHENTICATE");

    let modifiable = get_attribute(session, privkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let param_set = get_attribute(session, privkey, CKA_PARAMETER_SET, std::mem::size_of::<CK_ULONG>(), "CKA_PARAMETER_SET");
    assert_eq!(param_set, ulong_bytes(parameter_set), "CKA_PARAMETER_SET");

    let got_label = get_attribute(session, privkey, CKA_LABEL, label.len(), "CKA_LABEL");
    assert_eq!(got_label, label.as_bytes(), "CKA_LABEL");
}

#[test]
fn test_generated_mlkem() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generated_mlkem: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();

    // ML-KEM needs firmware >= 6.0, which already implies extended-slot
    // support (firmware >= 5.0), so SLOT_LIST_EXTENDED is always safe here.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 6, 0) {
        eprintln!(
            "skipping test_generated_mlkem: firmware {}.{} is older than the 6.0 ML-KEM requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let session = open_session(slot_id);

    for (parameter_set, ciphertext_len, value_len) in MLKEM_PARAMETER_SETS {
        let keys = generate_ml_kem_keys(session, SLOT_LIST_EXTENDED, parameter_set);

        let (privkey, pubkey) = keys[0];
        assert_mlkem_pubkey_attributes(
            session,
            pubkey,
            parameter_set,
            value_len,
            true,
            "Public key for PIV Authentication",
        );

        login_so(session, CKR_OK as CK_RV);
        assert_mlkem_privkey_attributes(
            session,
            privkey,
            parameter_set,
            true,
            false,
            "Private key for PIV Authentication",
        );
        logout(session, CKR_OK as CK_RV);

        for (privkey, pubkey) in keys {
            mlkem_decapsulate(session, privkey, pubkey, ciphertext_len);
        }
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_imported_mlkem() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_imported_mlkem: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();

    // ML-KEM needs firmware >= 6.0, which already implies extended-slot
    // support (firmware >= 5.0), so SLOT_LIST_EXTENDED is always safe here.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 6, 0) {
        eprintln!(
            "skipping test_imported_mlkem: firmware {}.{} is older than the 6.0 ML-KEM requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let session = open_session(slot_id);

    // Hardcoded, arbitrary seed material -- FIPS 203 doesn't require
    // anything special of the seed itself, any correctly-sized (64-byte)
    // byte string is a valid key seed, so there's no need to generate real
    // randomness for an import test.
    let seed = [0x24u8; 64];

    for (parameter_set, ciphertext_len, value_len) in MLKEM_PARAMETER_SETS {
        let keys = import_ml_kem_keys(session, SLOT_LIST_EXTENDED, parameter_set, &seed);

        let (privkey, pubkey) = keys[0];
        assert_mlkem_pubkey_attributes(
            session,
            pubkey,
            parameter_set,
            value_len,
            false,
            "Public key for PIV Authentication",
        );
        login_so(session, CKR_OK as CK_RV);
        assert_mlkem_privkey_attributes(
            session,
            privkey,
            parameter_set,
            false,
            false,
            "Private key for PIV Authentication",
        );
        logout(session, CKR_OK as CK_RV);

        for (privkey, pubkey) in keys {
            mlkem_decapsulate(session, privkey, pubkey, ciphertext_len);
        }
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}
