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

//! Ed25519 key generation, Ed25519 key import, and EdDSA sign/verify
//! hardware coverage

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

/// `CKA_EC_PARAMS` for Ed25519 isn't a real OID, it is encode it as a PrintableString
/// naming the curve instead, since RFC 8410 SPKI for EdDSA/X25519 carries no
/// AlgorithmIdentifier parameters to derive it from.
const ED25519_CURVE_PARAMS: &[u8] = &[
    0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
];


// A real Ed25519 private key (32-byte raw seed) and matching self-signed
// X.509 certificate (DER)
const ED25519_PRIV_KEY: &[u8] = &[
    0xf5, 0x84, 0xf4, 0x81, 0xee, 0x7e, 0x38, 0x59, 0x14, 0xf8, 0xff, 0x5c, 0x27, 0x64, 0x4b, 0x30, 0xc5, 0x31, 0x30,
    0x82, 0xff, 0xe0, 0xaf, 0x0c, 0x5f, 0xcb, 0xd7, 0x75, 0x74, 0x6d, 0xf4, 0xf2,
];

const ED25519_SELFSIGNED_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x6f, 0x30, 0x82, 0x01, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x23, 0x34, 0x24, 0x33,
    0xd5, 0xe9, 0xb9, 0xa8, 0x2b, 0x18, 0x0b, 0xf6, 0x06, 0xec, 0x66, 0xc9, 0xe1, 0xb4, 0x68, 0x53, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65,
    0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36,
    0x31, 0x31, 0x31, 0x30, 0x31, 0x34, 0x30, 0x35, 0x33, 0x36, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x31, 0x30, 0x37,
    0x31, 0x34, 0x30, 0x35, 0x33, 0x36, 0x5a, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x2a, 0x30,
    0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x07, 0xb7, 0x41, 0xe7, 0xfa, 0xcb, 0x68, 0xdf, 0x43, 0x84,
    0xda, 0x20, 0xb9, 0xfb, 0x2f, 0xe0, 0xab, 0x95, 0xca, 0xeb, 0xca, 0x87, 0xd7, 0x14, 0x6b, 0xca, 0x0a, 0xfd, 0x0a,
    0x34, 0x72, 0x89, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x24,
    0x13, 0x90, 0x2b, 0xcc, 0x48, 0x42, 0xb5, 0xa1, 0xba, 0xcc, 0x8a, 0x5e, 0x52, 0xb6, 0x68, 0x91, 0x35, 0x0b, 0xf6,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x24, 0x13, 0x90, 0x2b, 0xcc, 0x48,
    0x42, 0xb5, 0xa1, 0xba, 0xcc, 0x8a, 0x5e, 0x52, 0xb6, 0x68, 0x91, 0x35, 0x0b, 0xf6, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x41, 0x00, 0x25, 0x38, 0xde, 0x06, 0x59, 0xd6, 0x15, 0x44, 0xf3, 0xfa, 0xe2, 0xe1, 0x33, 0x52, 0x68, 0xcd,
    0xe5, 0xd4, 0x9b, 0xa9, 0xde, 0x3f, 0x96, 0xd1, 0xcc, 0x95, 0x45, 0xce, 0x46, 0xc5, 0x8d, 0x97, 0x68, 0xa7, 0x6b,
    0xd2, 0x51, 0xd0, 0xed, 0x4c, 0xf8, 0xaf, 0xa1, 0x43, 0xc4, 0xc2, 0xbb, 0xaa, 0xad, 0xa8, 0x20, 0x7d, 0xed, 0x32,
    0xfe, 0x76, 0xc9, 0x74, 0x90, 0x31, 0x81, 0x03, 0xa9, 0x0e,
];

fn generate_ed25519_keys(h_session: CK_SESSION_HANDLE, slots: &[u8]) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_EC_EDWARDS);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
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
        let mut public_key_template = [attr(CKA_CLASS, &class_pub), attr(CKA_ID, &id_bytes)];

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
        assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateKeyPair (Ed25519, slot {slot})");
        assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
        assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");
        generated.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    generated
}

fn import_ed25519_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    priv_key: &[u8],
    cert_der: &[u8],
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_cert = ulong_bytes(CKO_CERTIFICATE);
    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type = ulong_bytes(CKK_EC_EDWARDS);

    let mut imported = Vec::new();

    for slot in slots {
        let id_bytes = [*slot];

        let mut cert_template = [attr(CKA_CLASS, &class_cert), attr(CKA_ID, &id_bytes), attr(CKA_VALUE, cert_der)];
        let mut h_cert: CK_OBJECT_HANDLE = 0;
        let rv = unsafe {
            ykcs11::C_CreateObject(
                h_session,
                cert_template.as_mut_ptr(),
                cert_template.len() as CK_ULONG,
                &mut h_cert,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject (certificate, slot {slot})");
        assert_ne!(h_cert, 0, "C_CreateObject (certificate) returned a null handle");

        let mut private_key_template = [
            attr(CKA_CLASS, &class_priv),
            attr(CKA_KEY_TYPE, &key_type),
            attr(CKA_ID, &id_bytes),
            attr(CKA_EC_PARAMS, ED25519_CURVE_PARAMS),
            attr(CKA_VALUE, priv_key),
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
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject (private key, slot {slot})");
        assert_ne!(h_private_key, 0, "C_CreateObject (private key) returned a null handle");

        let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, *slot, "imported Ed25519 public key");

        imported.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    imported
}

fn eddsa_sign(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE, pubkey: Option<CK_OBJECT_HANDLE>) {
    login_user(session, CKR_OK as CK_RV);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let rv = unsafe { ykcs11::C_SignInit(session, &mut mechanism, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_SignInit");

    login_context_specific(session, CKR_OK as CK_RV);

    let data = vec![0x5au8; 32];
    let mut signature = vec![0u8; 64]; // Ed25519 signatures are always 64 bytes
    let mut signature_len = signature.len() as CK_ULONG;
    let rv = unsafe {
        ykcs11::C_Sign(
            session,
            data.as_ptr() as CK_BYTE_PTR,
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Sign");
    assert_eq!(signature_len as usize, signature.len(), "unexpected EdDSA signature length");

    if let Some(pk) = pubkey {
        let rv = unsafe { ykcs11::C_VerifyInit(session, &mut mechanism, pk) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit");
        let rv = unsafe {
            ykcs11::C_Verify(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature_len,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Verify");
    }

    logout(session, CKR_OK as CK_RV);
}

fn assert_ed25519_pubkey_attributes(session: CK_SESSION_HANDLE, pubkey: CK_OBJECT_HANDLE) {
    let class = get_attribute(session, pubkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PUBLIC_KEY), "CKA_CLASS");

    let token = get_attribute(session, pubkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, pubkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![0u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, pubkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC_EDWARDS), "CKA_KEY_TYPE");
}

fn assert_ed25519_privkey_attributes(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE) {
    login_user(session, CKR_OK as CK_RV);

    let class = get_attribute(session, privkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PRIVATE_KEY), "CKA_CLASS");

    let token = get_attribute(session, privkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, privkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![1u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, privkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC_EDWARDS), "CKA_KEY_TYPE");

    logout(session, CKR_OK as CK_RV);
}

#[test]
fn test_generated_ed25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generated_ed25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    // EdDSA mechanisms need firmware >= 5.7.
    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_generated_ed25519: firmware {}.{} is older than the 5.7 EdDSA requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let keys = generate_ed25519_keys(session, SLOT_LIST_EXTENDED);
    for (privkey, pubkey) in keys {
        eddsa_sign(session, privkey, Some(pubkey));
    }

    close_session(session);
}

#[test]
fn test_imported_ed25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_imported_ed25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_imported_ed25519: firmware {}.{} is older than the 5.7 EdDSA requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let keys = import_ed25519_keys(session, SLOT_LIST_EXTENDED, ED25519_PRIV_KEY, ED25519_SELFSIGNED_CERT_DER);
    for (privkey, pubkey) in keys {
        eddsa_sign(session, privkey, Some(pubkey));
    }

    close_session(session);
}

#[test]
fn test_key_attributes_ed25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_key_attributes_ed25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_key_attributes_ed25519: firmware {}.{} is older than the 5.7 EdDSA requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    const ID: u8 = 1; // 9a (Authentication)
    let keys = generate_ed25519_keys(session, &[ID]);
    let (privkey, pubkey) = keys[0];

    assert_ed25519_pubkey_attributes(session, pubkey);
    assert_ed25519_privkey_attributes(session, privkey);

    close_session(session);
}
