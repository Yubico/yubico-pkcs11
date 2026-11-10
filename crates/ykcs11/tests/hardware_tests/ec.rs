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

//! EC key generation, EC key import, ECDSA sign/verify and ECDH derivation hardware coverage

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

const P256_PEER_POINT: &[u8] = &[
    0x04, 0x07, 0x30, 0xdc, 0xbc, 0xd6, 0x07, 0xa5, 0x3c, 0x33, 0x51, 0x5b, 0x3f, 0x34, 0xf7, 0x80, 0x9c, 0x87, 0xcd,
    0xac, 0xff, 0xe8, 0xd9, 0x9b, 0x07, 0xf6, 0xc1, 0xe0, 0xa9, 0xbc, 0xf4, 0x82, 0x0b, 0x22, 0xde, 0x6d, 0x25, 0xc5,
    0x91, 0xfd, 0x59, 0xea, 0x52, 0x69, 0xe5, 0xee, 0x8d, 0xf5, 0x6c, 0xff, 0x5f, 0x2b, 0x5a, 0xaf, 0xed, 0x06, 0xe2,
    0xa6, 0x64, 0x53, 0x61, 0x88, 0x19, 0x4e, 0xad,
];
const P384_PEER_POINT: &[u8] = &[
    0x04, 0x34, 0x90, 0x98, 0xdd, 0xf3, 0xa2, 0x51, 0x20, 0x2f, 0xef, 0x02, 0x38, 0x89, 0x83, 0x07, 0xd5, 0x91, 0x5a,
    0x38, 0xc3, 0xa1, 0x88, 0xec, 0x16, 0x6b, 0xc2, 0xeb, 0x57, 0xd1, 0x40, 0xe3, 0xd6, 0x01, 0xa4, 0x73, 0x21, 0xb9,
    0xbb, 0xc4, 0x99, 0x77, 0x81, 0xc9, 0x2a, 0x1c, 0xbc, 0x47, 0x75, 0x04, 0xeb, 0x60, 0x03, 0xaa, 0xdf, 0xac, 0x37,
    0x9f, 0x63, 0xe4, 0x28, 0x40, 0x0f, 0xf5, 0x7f, 0xc6, 0x15, 0x67, 0xd6, 0x8f, 0x30, 0x3b, 0x60, 0x77, 0xae, 0xcf,
    0xad, 0xed, 0x69, 0x21, 0xe4, 0xa0, 0x8f, 0xb4, 0x75, 0x50, 0x60, 0x42, 0x30, 0x06, 0x5c, 0x75, 0xb8, 0xd3, 0x64,
    0xea, 0x1a,
];

const P256_PRIV_KEY: &[u8] = &[
    0x0c, 0x59, 0xd6, 0xad, 0x68, 0x81, 0x0b, 0x69, 0xc1, 0x7f, 0x40, 0x6e, 0x33, 0x78, 0x7b, 0x97, 0x00, 0xf5, 0x1c,
    0xa4, 0xc0, 0x54, 0xd9, 0x77, 0xb1, 0x67, 0x30, 0x86, 0x3e, 0x6c, 0x66, 0x03,
];
const P384_PRIV_KEY: &[u8] = &[
    0x9c, 0xd0, 0x8e, 0xd8, 0x58, 0xff, 0x0f, 0xce, 0x30, 0x09, 0x98, 0x4d, 0x2e, 0xd7, 0x17, 0x5e, 0x05, 0xa6, 0x6a,
    0x59, 0xd1, 0xea, 0x93, 0x70, 0x2a, 0x18, 0x6a, 0xfe, 0x14, 0x3a, 0x92, 0x10, 0xc4, 0xa0, 0xf3, 0xdc, 0x3c, 0x69,
    0x5f, 0xcc, 0x7a, 0x47, 0x1d, 0xce, 0xfd, 0xb7, 0x81, 0xba,
];

const P256_SELFSIGNED_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0xaf, 0x30, 0x82, 0x01, 0x55, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x37, 0xa7, 0xfe, 0x22,
    0x70, 0x9c, 0x93, 0x9e, 0x7c, 0xe6, 0xb0, 0xab, 0x2d, 0x3c, 0xec, 0x4d, 0x5b, 0x15, 0xdb, 0x9e, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x30, 0x36, 0x31, 0x36, 0x31, 0x34, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x31, 0x31, 0x30, 0x33, 0x31, 0x36, 0x31, 0x34, 0x30, 0x39, 0x5a, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75,
    0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x24, 0x0c, 0xca, 0xb7, 0x84, 0x29, 0x6e, 0xb4, 0xcc,
    0xad, 0x9d, 0xe7, 0x67, 0xd3, 0x34, 0x3b, 0xab, 0xa3, 0xd0, 0xc4, 0xe9, 0x2f, 0x51, 0x6e, 0xfd, 0x86, 0x81, 0x9e,
    0x45, 0x67, 0x8f, 0xa0, 0x4b, 0x21, 0x1b, 0x2a, 0xe0, 0xd6, 0x3a, 0xa2, 0xe6, 0xa0, 0xd0, 0x98, 0x46, 0x71, 0xb0,
    0xab, 0x86, 0x68, 0x2a, 0x8b, 0x96, 0xb4, 0x51, 0x24, 0xd9, 0xf5, 0x4c, 0x6c, 0xb2, 0x03, 0x71, 0x07, 0xa3, 0x53,
    0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x60, 0xdb, 0x75, 0xe2, 0xa9, 0xc1,
    0x86, 0x46, 0xc7, 0x6b, 0xf2, 0x31, 0x0b, 0x05, 0xdb, 0x57, 0xf6, 0x33, 0x31, 0xd0, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x60, 0xdb, 0x75, 0xe2, 0xa9, 0xc1, 0x86, 0x46, 0xc7, 0x6b, 0xf2,
    0x31, 0x0b, 0x05, 0xdb, 0x57, 0xf6, 0x33, 0x31, 0xd0, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x21, 0xe6, 0x69, 0xab, 0xc5, 0xc0, 0x48, 0xb3, 0xd7, 0x74, 0xcd, 0xb9,
    0x57, 0xb1, 0xab, 0xd2, 0x4d, 0xc1, 0x3a, 0x20, 0xcf, 0x21, 0x4e, 0x93, 0x82, 0x26, 0x79, 0xf1, 0x53, 0x3e, 0x96,
    0xb9, 0x02, 0x21, 0x00, 0xa9, 0x9f, 0xb8, 0x3e, 0x6a, 0x27, 0x68, 0xad, 0x9f, 0x31, 0x30, 0xd5, 0x84, 0x6a, 0x96,
    0x7f, 0xbd, 0x37, 0x46, 0x13, 0x87, 0x1b, 0xe4, 0xd8, 0x48, 0x1c, 0x69, 0xd8, 0x7d, 0x17, 0xf9, 0x59,
];
const P384_SELFSIGNED_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0xed, 0x30, 0x82, 0x01, 0x72, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x5c, 0xb0, 0x36, 0x82,
    0x73, 0xf3, 0xe6, 0x24, 0x31, 0xf5, 0x4e, 0x6f, 0x53, 0x45, 0x82, 0x25, 0x4a, 0x02, 0x12, 0xf7, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x30, 0x36, 0x31, 0x36, 0x31, 0x34, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x31, 0x31, 0x30, 0x33, 0x31, 0x36, 0x31, 0x34, 0x30, 0x39, 0x5a, 0x30, 0x2d, 0x31, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75,
    0x65, 0x72, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
    0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xc5, 0x10, 0x83, 0x3e, 0xfe, 0xa5, 0xf6, 0x37, 0xa1, 0xbf, 0xba, 0x3a,
    0x0f, 0xf2, 0xe8, 0x3d, 0xed, 0x27, 0xea, 0xfa, 0xf6, 0x39, 0xaa, 0xff, 0x65, 0x04, 0x39, 0x28, 0x91, 0xc4, 0x86,
    0x74, 0x24, 0x92, 0xbc, 0xb0, 0x68, 0x62, 0x0d, 0xd7, 0x7c, 0x31, 0x0f, 0x55, 0x64, 0x3c, 0x2c, 0x51, 0x3f, 0x6c,
    0xc9, 0xd6, 0x05, 0xf0, 0x6a, 0x23, 0x5b, 0x57, 0x31, 0x22, 0x90, 0xe4, 0x13, 0x55, 0x1c, 0x6f, 0x0a, 0x4a, 0x05,
    0xa0, 0xb2, 0x44, 0xcf, 0xaf, 0xe6, 0x9a, 0x65, 0xc9, 0xe6, 0x1d, 0x5d, 0x87, 0x69, 0x1c, 0x94, 0x86, 0x77, 0x43,
    0xcd, 0x3d, 0x09, 0x16, 0x92, 0x19, 0x5e, 0xe8, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0xeb, 0x7b, 0xba, 0x99, 0x6f, 0x25, 0x36, 0x20, 0x8d, 0xbf, 0xd4, 0xa6, 0xbd, 0xf1, 0x8d,
    0xbb, 0x87, 0x3e, 0xbd, 0x8b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xeb,
    0x7b, 0xba, 0x99, 0x6f, 0x25, 0x36, 0x20, 0x8d, 0xbf, 0xd4, 0xa6, 0xbd, 0xf1, 0x8d, 0xbb, 0x87, 0x3e, 0xbd, 0x8b,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02, 0x31, 0x00, 0xe6,
    0x97, 0x8e, 0xbf, 0xf3, 0x12, 0x2d, 0x1f, 0xe8, 0x07, 0xca, 0xef, 0xff, 0x82, 0x50, 0x39, 0xcd, 0xfc, 0xb1, 0x88,
    0xc6, 0x88, 0x9a, 0xdb, 0x67, 0xcb, 0xfd, 0xa7, 0x1f, 0x2f, 0x1a, 0xdf, 0xd1, 0x15, 0xdd, 0x4d, 0x44, 0xf1, 0xe4,
    0xf8, 0x4a, 0xd8, 0x82, 0x90, 0x3e, 0x47, 0xc5, 0x43, 0x02, 0x31, 0x00, 0xde, 0x02, 0xb3, 0x64, 0x14, 0xea, 0xfa,
    0x60, 0xfa, 0xf3, 0x51, 0x08, 0x8e, 0xea, 0xd8, 0xe8, 0xb1, 0x82, 0x33, 0x85, 0x1f, 0x2a, 0x50, 0x45, 0x1c, 0x71,
    0xe3, 0xcc, 0x2d, 0x83, 0x0d, 0x6a, 0x19, 0x3c, 0xee, 0x11, 0x1b, 0x3f, 0x29, 0x62, 0xcc, 0xfb, 0x9a, 0x46, 0xff,
    0xa4, 0x35, 0x53,
];


const CKA_YUBICO_TOUCH_POLICY: u32 = 0xd9554201;
const CKA_YUBICO_PIN_POLICY: u32 = 0xd9554202;
const TOUCH_POLICY_ALWAYS: u8 = 2;
const TOUCH_POLICY_CACHED: u8 = 3;
const TOUCH_POLICY_NEVER: u8 = 1;
const PIN_POLICY_ALWAYS: u8 = 3;
const PIN_POLICY_ONCE: u8 = 2;
const PIN_POLICY_NEVER: u8 = 1;

pub(crate) fn generate_ec_keys(h_session: CK_SESSION_HANDLE, slots: &[u8], ec_params: &[u8]) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>{
    let rv = unsafe {
        ykcs11::C_Login(
            h_session,
            CKU_SO as CK_USER_TYPE,
            DEFAULT_MGMT_KEY_HEX.as_ptr() as CK_UTF8CHAR_PTR,
            DEFAULT_MGMT_KEY_HEX.len() as CK_ULONG,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Login(CKU_SO)");

    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_EC);
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
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
            attr(CKA_EC_PARAMS, ec_params),
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
        assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateKeyPair (slot {slot})");
        assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
        assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");
        generated.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    generated
}

fn generate_ec_key_with_policy(
    session: CK_SESSION_HANDLE,
    id: u8,
    ec_params: &[u8],
    touch_policy: Option<u8>,
    pin_policy: Option<u8>,
    always_auth: bool,
) -> CK_OBJECT_HANDLE {
    let id_bytes = [id];
    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let class_pub = ulong_bytes(CKO_PUBLIC_KEY);
    let key_type = ulong_bytes(CKK_EC);
    let touch_byte = touch_policy.map(|t| [t]);
    let pin_byte = pin_policy.map(|p| [p]);
    let always_auth_byte = [always_auth as u8];

    let mut private_key_template = vec![
        attr(CKA_CLASS, &class_priv),
        attr(CKA_KEY_TYPE, &key_type),
        attr(CKA_ID, &id_bytes),
    ];
    if let Some(ref touch_byte) = touch_byte {
        private_key_template.push(attr(CKA_YUBICO_TOUCH_POLICY, touch_byte));
    }
    if let Some(ref pin_byte) = pin_byte {
        private_key_template.push(attr(CKA_YUBICO_PIN_POLICY, pin_byte));
    }
    if always_auth {
        private_key_template.push(attr(CKA_ALWAYS_AUTHENTICATE, &always_auth_byte));
    }

    let mut public_key_template = [
        attr(CKA_CLASS, &class_pub),
        attr(CKA_ID, &id_bytes),
        attr(CKA_EC_PARAMS, ec_params),
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut h_public_key: CK_OBJECT_HANDLE = 0;
    let mut h_private_key: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_GenerateKeyPair(
            session,
            &mut mechanism,
            public_key_template.as_mut_ptr(),
            public_key_template.len() as CK_ULONG,
            private_key_template.as_mut_ptr(),
            private_key_template.len() as CK_ULONG,
            &mut h_public_key,
            &mut h_private_key,
        )
    };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GenerateKeyPair (with policy)");
    assert_ne!(h_private_key, 0, "C_GenerateKeyPair returned a null private key handle");
    assert_ne!(h_public_key, 0, "C_GenerateKeyPair returned a null public key handle");

    h_private_key
}

pub(crate) fn import_ec_keys(
    h_session: CK_SESSION_HANDLE,
    slots: &[u8],
    ec_params: &[u8],
    priv_key: &[u8],
    cert_der: &[u8],
) -> Vec<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
    login_so(h_session, CKR_OK as CK_RV);

    let class_cert = ulong_bytes(CKO_CERTIFICATE);
    let class_priv = ulong_bytes(CKO_PRIVATE_KEY);
    let key_type = ulong_bytes(CKK_EC);

    let mut imported = Vec::new();

    for slot in slots {
        let id_bytes = [*slot];

        let mut cert_template = [
            attr(CKA_CLASS, &class_cert),
            attr(CKA_ID, &id_bytes),
            attr(CKA_VALUE, cert_der),
        ];
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
            attr(CKA_EC_PARAMS, ec_params),
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

        let h_public_key = find_object_handle(h_session, CKO_PUBLIC_KEY, *slot, "imported EC public key");

        imported.push((h_private_key, h_public_key));
    }

    logout(h_session, CKR_OK as CK_RV);

    imported
}

// CKM_ECDSA_SHA{1,256,384,512} hash an arbitrary-length message themselves
// before signing, unlike bare CKM_ECDSA which expects raw, pre-hashed input
// exactly curve_len bytes long
const ECDSA_HASHED_MECHANISMS: [CK_MECHANISM_TYPE; 4] = [
    CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE,
    CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
    CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
    CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
];

pub(crate) fn ecdsa_sign(session: CK_SESSION_HANDLE, privkey: CK_OBJECT_HANDLE, pubkey: Option<CK_OBJECT_HANDLE>, curve_len: usize) {
    login_user(session, CKR_OK as CK_RV);

    _ecdsa_sign(session, privkey, pubkey, CKM_ECDSA as CK_MECHANISM_TYPE, &vec![0x5au8; curve_len], curve_len);
    for mechanism in ECDSA_HASHED_MECHANISMS {
        _ecdsa_sign(session, privkey, pubkey, mechanism, &vec![0x5au8; 32], curve_len);
    }

    logout(session, CKR_OK as CK_RV);
}

fn _ecdsa_sign(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    pubkey: Option<CK_OBJECT_HANDLE>,
    mechanism_type: CK_MECHANISM_TYPE,
    data: &Vec<u8>,
    curve_len: usize,
) {
    let mut sign_mechanism = CK_MECHANISM {
        mechanism: mechanism_type,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let rv = unsafe { ykcs11::C_SignInit(session, &mut sign_mechanism, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_SignInit (mechanism {mechanism_type:#x})");

    login_context_specific(session, CKR_OK as CK_RV);

    let mut signature = vec![0u8; curve_len * 2]; // r || s
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
    assert_eq!(rv, CKR_OK as CK_RV, "C_Sign (mechanism {mechanism_type:#x})");
    assert_eq!(
        signature_len as usize,
        signature.len(),
        "unexpected ECDSA signature length (mechanism {mechanism_type:#x})"
    );

    if let Some(pk) = pubkey {
        let rv = unsafe { ykcs11::C_VerifyInit(session, &mut sign_mechanism, pk) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_VerifyInit (mechanism {mechanism_type:#x})");
        let rv = unsafe {
            ykcs11::C_Verify(
                session,
                data.as_ptr() as CK_BYTE_PTR,
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature_len,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Verify (mechanism {mechanism_type:#x})");
    }
}

fn derive_ecdh(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    peer_point: &[u8],
    secret_len: usize,
) -> Vec<u8> {
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

fn assert_policy(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    expected_touch: Option<u8>,
    expected_pin: u8) {
    if let Some(expected_touch) = expected_touch {
        let touch = get_attribute(session, privkey, CKA_YUBICO_TOUCH_POLICY, 1, "CKA_YUBICO_TOUCH_POLICY");
        assert_eq!(touch, vec![expected_touch], "CKA_YUBICO_TOUCH_POLICY");
    }

    let pin = get_attribute(session, privkey, CKA_YUBICO_PIN_POLICY, 1, "CKA_YUBICO_PIN_POLICY");
    assert_eq!(pin, vec![expected_pin], "CKA_YUBICO_PIN_POLICY");

    let always_auth = get_attribute(session, privkey, CKA_ALWAYS_AUTHENTICATE, 1, "CKA_ALWAYS_AUTHENTICATE");
    let expected_always_auth = (expected_pin == PIN_POLICY_ALWAYS) as u8;
    assert_eq!(always_auth, vec![expected_always_auth], "CKA_ALWAYS_AUTHENTICATE");
}

fn assert_ec_pubkey_attributes(session: CK_SESSION_HANDLE, pubkey: CK_OBJECT_HANDLE, ec_params: &[u8], ec_point_len: usize) {
    let class = get_attribute(session, pubkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PUBLIC_KEY), "CKA_CLASS");

    let token = get_attribute(session, pubkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, pubkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![0u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, pubkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC), "CKA_KEY_TYPE");

    let trusted = get_attribute(session, pubkey, CKA_TRUSTED, 1, "CKA_TRUSTED");
    assert_eq!(trusted, vec![0u8], "CKA_TRUSTED");

    let local = get_attribute(session, pubkey, CKA_LOCAL, 1, "CKA_LOCAL");
    assert_eq!(local, vec![1u8], "CKA_LOCAL");

    let encrypt = get_attribute(session, pubkey, CKA_ENCRYPT, 1, "CKA_ENCRYPT");
    assert_eq!(encrypt, vec![1u8], "CKA_ENCRYPT");

    let verify = get_attribute(session, pubkey, CKA_VERIFY, 1, "CKA_VERIFY");
    assert_eq!(verify, vec![1u8], "CKA_VERIFY");

    let wrap = get_attribute(session, pubkey, CKA_WRAP, 1, "CKA_WRAP");
    assert_eq!(wrap, vec![0u8], "CKA_WRAP");

    let derive = get_attribute(session, pubkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![1u8], "CKA_DERIVE");

    let modifiable = get_attribute(session, pubkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let params = get_attribute(session, pubkey, CKA_EC_PARAMS, ec_params.len(), "CKA_EC_PARAMS");
    assert_eq!(params, ec_params, "CKA_EC_PARAMS");

    let point = get_attribute(session, pubkey, CKA_EC_POINT, ec_point_len, "CKA_EC_POINT");
    assert_eq!(point.len(), ec_point_len, "CKA_EC_POINT length");
}

fn assert_ec_privkey_attributes(
    session: CK_SESSION_HANDLE,
    privkey: CK_OBJECT_HANDLE,
    ec_params: &[u8],
    ec_point_len: usize,
    expected_always_auth: bool,
) {
    let class = get_attribute(session, privkey, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
    assert_eq!(class, ulong_bytes(CKO_PRIVATE_KEY), "CKA_CLASS");

    let token = get_attribute(session, privkey, CKA_TOKEN, 1, "CKA_TOKEN");
    assert_eq!(token, vec![1u8], "CKA_TOKEN");

    let private = get_attribute(session, privkey, CKA_PRIVATE, 1, "CKA_PRIVATE");
    assert_eq!(private, vec![1u8], "CKA_PRIVATE");

    let key_type = get_attribute(session, privkey, CKA_KEY_TYPE, std::mem::size_of::<CK_ULONG>(), "CKA_KEY_TYPE");
    assert_eq!(key_type, ulong_bytes(CKK_EC), "CKA_KEY_TYPE");

    let sensitive = get_attribute(session, privkey, CKA_SENSITIVE, 1, "CKA_SENSITIVE");
    assert_eq!(sensitive, vec![1u8], "CKA_SENSITIVE");

    let always_sensitive = get_attribute(session, privkey, CKA_ALWAYS_SENSITIVE, 1, "CKA_ALWAYS_SENSITIVE");
    assert_eq!(always_sensitive, vec![1u8], "CKA_ALWAYS_SENSITIVE");

    let extractable = get_attribute(session, privkey, CKA_EXTRACTABLE, 1, "CKA_EXTRACTABLE");
    assert_eq!(extractable, vec![0u8], "CKA_EXTRACTABLE");

    let never_extractable = get_attribute(session, privkey, CKA_NEVER_EXTRACTABLE, 1, "CKA_NEVER_EXTRACTABLE");
    assert_eq!(never_extractable, vec![1u8], "CKA_NEVER_EXTRACTABLE");

    let local = get_attribute(session, privkey, CKA_LOCAL, 1, "CKA_LOCAL");
    assert_eq!(local, vec![1u8], "CKA_LOCAL");

    let decrypt = get_attribute(session, privkey, CKA_DECRYPT, 1, "CKA_DECRYPT");
    assert_eq!(decrypt, vec![1u8], "CKA_DECRYPT");

    let sign = get_attribute(session, privkey, CKA_SIGN, 1, "CKA_SIGN");
    assert_eq!(sign, vec![1u8], "CKA_SIGN");

    let derive = get_attribute(session, privkey, CKA_DERIVE, 1, "CKA_DERIVE");
    assert_eq!(derive, vec![0u8], "CKA_DERIVE");

    let always_auth = get_attribute(session, privkey, CKA_ALWAYS_AUTHENTICATE, 1, "CKA_ALWAYS_AUTHENTICATE");
    assert_eq!(always_auth, vec![expected_always_auth as u8], "CKA_ALWAYS_AUTHENTICATE");

    let modifiable = get_attribute(session, privkey, CKA_MODIFIABLE, 1, "CKA_MODIFIABLE");
    assert_eq!(modifiable, vec![0u8], "CKA_MODIFIABLE");

    let params = get_attribute(session, privkey, CKA_EC_PARAMS, ec_params.len(), "CKA_EC_PARAMS");
    assert_eq!(params, ec_params, "CKA_EC_PARAMS");

    let point = get_attribute(session, privkey, CKA_EC_POINT, ec_point_len, "CKA_EC_POINT");
    assert_eq!(point.len(), ec_point_len, "CKA_EC_POINT length");
}

#[test]
fn test_generated_eccp256() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generate_eccp256: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id.clone());
    let keys = if firmware_at_least(&token_info(slot_id), 5, 0) {
        generate_ec_keys(session, SLOT_LIST_EXTENDED, P256_EC_PARAMS)
    } else {
        generate_ec_keys(session, SLOT_LIST, P256_EC_PARAMS)
    };

    let (privkey, pubkey) = keys[0];
    assert_ec_pubkey_attributes(session, pubkey, P256_EC_PARAMS, 67);
    login_so(session, CKR_OK as CK_RV);
    assert_ec_privkey_attributes(session, privkey, P256_EC_PARAMS, 67, false);
    logout(session, CKR_OK as CK_RV);

    for (privkey, pubkey) in keys {
        ecdsa_sign(session, privkey, Some(pubkey), 32);
        let secret_a = derive_ecdh(session, privkey, P256_PEER_POINT, 32);
        let secret_b = derive_ecdh(session, privkey, P256_PEER_POINT, 32);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_generated_eccp384() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generate_eccp384: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);
    let keys = if firmware_at_least(&token_info(slot_id), 5, 0) {
        generate_ec_keys(session, SLOT_LIST_EXTENDED, P384_EC_PARAMS)
    } else {
        generate_ec_keys(session, SLOT_LIST, P384_EC_PARAMS)
    };

    let (privkey, pubkey) = keys[0];
    assert_ec_pubkey_attributes(session, pubkey, P384_EC_PARAMS, 99);
    login_so(session, CKR_OK as CK_RV);
    assert_ec_privkey_attributes(session, privkey, P384_EC_PARAMS, 99, false);
    logout(session, CKR_OK as CK_RV);

    for (privkey, pubkey) in keys {
        ecdsa_sign(session, privkey, Some(pubkey), 48);
        let secret_a = derive_ecdh(session, privkey, P384_PEER_POINT, 48);
        let secret_b = derive_ecdh(session, privkey, P384_PEER_POINT, 48);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_imported_eccp256() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_import_eccp256: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);
    let keys = if firmware_at_least(&token_info(slot_id), 5, 0) {
        import_ec_keys(session, SLOT_LIST_EXTENDED, P256_EC_PARAMS, P256_PRIV_KEY, P256_SELFSIGNED_CERT_DER)
    } else {
        import_ec_keys(session, SLOT_LIST, P256_EC_PARAMS, P256_PRIV_KEY, P256_SELFSIGNED_CERT_DER)
    };

    for (privkey, pubkey) in keys {
        ecdsa_sign(session, privkey, Some(pubkey), 32);
        let secret_a = derive_ecdh(session, privkey, P256_PEER_POINT, 32);
        let secret_b = derive_ecdh(session, privkey, P256_PEER_POINT, 32);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_imported_eccp384() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_import_eccp384: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);
    let keys = if firmware_at_least(&token_info(slot_id), 5, 0) {
        import_ec_keys(session, SLOT_LIST_EXTENDED, P384_EC_PARAMS, P384_PRIV_KEY, P384_SELFSIGNED_CERT_DER)
    } else {
        import_ec_keys(session, SLOT_LIST, P384_EC_PARAMS, P384_PRIV_KEY, P384_SELFSIGNED_CERT_DER)
    };

    for (privkey, pubkey) in keys {
        ecdsa_sign(session, privkey, Some(pubkey), 48);
        let secret_a = derive_ecdh(session, privkey, P384_PEER_POINT, 48);
        let secret_b = derive_ecdh(session, privkey, P384_PEER_POINT, 48);
        assert_eq!(secret_a, secret_b, "CKM_ECDH1_DERIVE wasn't deterministic for the same peer point");
    }

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

#[test]
fn test_generate_eccp256_with_policy() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_generate_eccp256_with_policy: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);
    login_so(session, CKR_OK as CK_RV);

    const ID: u8 = 1; // 9a (Authentication). Reuse and overwritten every iteration.
    const TOUCH_POLICIES: [u8; 3] = [TOUCH_POLICY_ALWAYS, TOUCH_POLICY_CACHED, TOUCH_POLICY_NEVER];
    const PIN_POLICIES: [u8; 3] = [PIN_POLICY_ALWAYS, PIN_POLICY_ONCE, PIN_POLICY_NEVER];

    for &touch_policy in &TOUCH_POLICIES {
        for &pin_policy in &PIN_POLICIES {
            let privkey =
                generate_ec_key_with_policy(session, ID, P256_EC_PARAMS, Some(touch_policy), Some(pin_policy), false);
            assert_policy(session, privkey, Some(touch_policy), pin_policy);
            let rv = unsafe { ykcs11::C_DestroyObject(session, privkey) };
            assert_eq!(rv, CKR_OK as CK_RV, "C_DestroyObject");
        }
    }

    // CKA_ALWAYS_AUTHENTICATE=TRUE with no explicit CKA_YUBICO_PIN_POLICY.
    // template.rs's resolve_policies() deterministically upgrades a Default
    // PIN policy to Always in that case
    let privkey = generate_ec_key_with_policy(session, ID, P256_EC_PARAMS, None, None, true);
    assert_policy(session, privkey, None, PIN_POLICY_ALWAYS);
    let rv = unsafe { ykcs11::C_DestroyObject(session, privkey) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_DestroyObject");

    logout(session, CKR_OK as CK_RV);

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}
