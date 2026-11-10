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

//! X25519 key generation, X25519 key import, and ECDH key-agreement
//! hardware coverage

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

/// `CKA_EC_PARAMS` for X25519 isn't a real OID, same as Ed25519's
const X25519_CURVE_PARAMS: &[u8] = &[
    0x13, 0x0b, b'c', b'u', b'r', b'v', b'e', b'2', b'5', b'5', b'1', b'9',
];

// A real X25519 private key (32-byte raw scalar) and matching
// X.509 certificate (DER, signed by a throwaway Ed25519 key since X25519
// itself can't sign
const X25519_PRIV_KEY: &[u8] = &[
    0xe0, 0x20, 0xc2, 0x06, 0x26, 0x2c, 0x02, 0x48, 0x82, 0xcd, 0x8a, 0x11, 0x3c, 0xe4, 0xca, 0x0f, 0x28, 0x89, 0xd0,
    0x72, 0x5e, 0xdc, 0xa8, 0xfc, 0xa2, 0x3d, 0x5a, 0xc7, 0xfe, 0x2b, 0x75, 0x60,
];

const X25519_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x2e, 0x30, 0x81, 0xe1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x15, 0x1c, 0x00, 0xe0, 0x0b,
    0xc9, 0xb7, 0xff, 0x13, 0xef, 0x3b, 0x7e, 0xb3, 0x7b, 0x76, 0xb7, 0x29, 0x63, 0x2d, 0x43, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31,
    0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x31, 0x30, 0x37, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x2a, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, 0x9b, 0x2c, 0x8a, 0x9d, 0x6b, 0xa1, 0x5d, 0x9f, 0xed, 0xc0, 0x5f,
    0x52, 0xbd, 0x91, 0x2f, 0x72, 0xbd, 0xb1, 0xc3, 0xe0, 0x37, 0x28, 0x2a, 0xa2, 0x37, 0x61, 0xdf, 0x6f, 0xdd, 0x94,
    0xf1, 0x46, 0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x0c, 0x8c, 0xc0, 0xd0, 0x00,
    0xa9, 0x58, 0x99, 0xba, 0x34, 0xa1, 0xa5, 0x76, 0xbf, 0xf1, 0xf2, 0xb6, 0x89, 0xb0, 0x89, 0x89, 0x1e, 0xd3, 0xb3,
    0x56, 0x7c, 0xa2, 0x70, 0x9c, 0x42, 0x91, 0xa0, 0xf6, 0x20, 0xcb, 0x0e, 0xbf, 0x1f, 0xcc, 0xdb, 0x58, 0x4c, 0x19,
    0x79, 0xff, 0xdb, 0x85, 0x79, 0x53, 0xc5, 0xd0, 0xbd, 0xe7, 0x97, 0xd1, 0xc6, 0x32, 0x33, 0x8e, 0xd6, 0x19, 0x54,
    0x37, 0x03,
];

const X25519_PEER_POINT: &[u8] = &[
    0xf6, 0xab, 0xfd, 0x88, 0x29, 0xd7, 0xc9, 0x5a, 0x09, 0x45, 0xde, 0x11, 0x09, 0x21, 0xfe, 0xfd, 0xef, 0x5e, 0x5e,
    0x44, 0xfc, 0x18, 0xc7, 0xbe, 0xd2, 0xa0, 0x19, 0xb9, 0x44, 0xee, 0x01, 0x20,
];

fn generate_x25519_keys(h_session: CK_SESSION_HANDLE, slots: &[u8]) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_EC_MONTGOMERY);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
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
        assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateKeyPair (X25519, slot {slot})");
        assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
        assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");
        generated.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    generated
}

fn import_x25519_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    priv_key: &[u8],
    cert_der: &[u8],
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_cert = ulong_bytes(CKO_CERTIFICATE);
    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type = ulong_bytes(CKK_EC_MONTGOMERY);

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
            attr(CKA_EC_PARAMS, X25519_CURVE_PARAMS),
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

        let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, *slot, "imported X25519 public key");

        imported.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    imported
}

/// X25519 key agreement (there is no `CKM_X25519` in this backend.
/// `derive.rs` dispatches `CKM_ECDH1_DERIVE` on the base key's actual key
/// type, reusing the same `CK_ECDH1_DERIVE_PARAMS` struct as NIST EC. The
/// only difference from `ec.rs`'s `derive_ecdh` is that the peer point is a
/// raw 32-byte Montgomery u-coordinate instead of a SEC1-encoded point.
fn derive_x25519(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE, peer_point: &[u8], secret_len: usize) -> Vec<u8> {
    let not_token = [0u8];
    let class = ulong_bytes(CKO_SECRET_KEY);
    let key_type = ulong_bytes(CKK_GENERIC_SECRET);
    let extractable = [1u8];
    let mut template = [
        attr(CKA_TOKEN, &not_token),
        attr(CKA_CLASS, &class),
        attr(CKA_KEY_TYPE, &key_type),
        attr(CKA_EXTRACTABLE, &extractable),
    ];

    let params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL as CK_ULONG,
        ulSharedDataLen: 0,
        pSharedData: ptr::null_mut(),
        ulPublicDataLen: peer_point.len() as CK_ULONG,
        pPublicData: peer_point.as_ptr() as CK_BYTE_PTR,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
        pParameter: &params as *const CK_ECDH1_DERIVE_PARAMS as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };

    login_user(session, CKR_OK as CK_RV);

    let mut h_secret: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_DeriveKey(
            session,
            &mut mechanism,
            privkey,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut h_secret,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_DeriveKey");
    assert_ne!(h_secret, 0, "C_DeriveKey returned a null handle");
    let secret = get_attribute(session, h_secret, CKA_VALUE, secret_len, "derived secret");

    logout(session, CKR_OK as CK_RV);
    secret
}

fn assert_x25519_pubkey_attributes(session: CK_SESSION_HANDLE, pubkey: CK_OBJECT_HANDLE) {
    let class = get_attribute(session, pubkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PUBLIC_KEY), "CKA_CLASS");

    let token = get_attribute(session, pubkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, pubkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![0u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, pubkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC_MONTGOMERY), "CKA_KEY_TYPE");

    let point = get_attribute(session, pubkey, CKA_EC_POINT, 34, "CKA_EC_POINT");
    assert_eq!(point.len(), 34, "CKA_EC_POINT length");

    let derive = get_attribute(session, pubkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![1u8], "CKA_DERIVE");
}

fn assert_x25519_privkey_attributes(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE) {
    let class = get_attribute(session, privkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PRIVATE_KEY), "CKA_CLASS");

    let token = get_attribute(session, privkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, privkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![1u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, privkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC_MONTGOMERY), "CKA_KEY_TYPE");

    let point = get_attribute(session, privkey, CKA_EC_POINT, 34, "CKA_EC_POINT");
    assert_eq!(point.len(), 34, "CKA_EC_POINT length");

    let derive = get_attribute(session, privkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![0u8], "CKA_DERIVE");
}

#[test]
fn test_generated_x25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generated_x25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_generated_x25519: firmware {}.{} is older than the 5.7 X25519 requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let keys = generate_x25519_keys(session, SLOT_LIST_EXTENDED);
    for (privkey, _pubkey) in keys {
        let secret_a = derive_x25519(session, privkey, X25519_PEER_POINT, 32);
        let secret_b = derive_x25519(session, privkey, X25519_PEER_POINT, 32);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_imported_x25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_imported_x25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_imported_x25519: firmware {}.{} is older than the 5.7 X25519 requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    let keys = import_x25519_keys(session, SLOT_LIST_EXTENDED, X25519_PRIV_KEY, X25519_CERT_DER);
    for (privkey, _pubkey) in keys {
        let secret_a = derive_x25519(session, privkey, X25519_PEER_POINT, 32);
        let secret_b = derive_x25519(session, privkey, X25519_PEER_POINT, 32);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_key_attributes_x25519() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_key_attributes_x25519: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    let info = token_info(slot_id);
    if !firmware_at_least(&info, 5, 7) {
        eprintln!(
            "skipping test_key_attributes_x25519: firmware {}.{} is older than the 5.7 X25519 requires",
            info.firmwareVersion.major, info.firmwareVersion.minor
        );
        return;
    }

    const ID: u8 = 2; // 9c (Signature)
    let keys = generate_x25519_keys(session, &[ID]);
    let (privkey, pubkey) = keys[0];

    assert_x25519_pubkey_attributes(session, pubkey);
    login_so(session, CKR_OK as CK_RV);
    assert_x25519_privkey_attributes(session, privkey);
    logout(session, CKR_OK as CK_RV);

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}
