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

//! `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` hardware coverage

use crate::ec::generate_ec_keys;
use crate::util::*;
use pkcs11_sys::*;

fn find_objects(
    h_session: CK_SESSION_HANDLE,
    template: &mut [CK_ATTRIBUTE],
    max_count: usize,
    what: &str,
) -> Vec<CK_OBJECT_HANDLE> {
    let rv = unsafe {
        ykcs11::C_FindObjectsInit(h_session, template.as_mut_ptr(), template.len() as CK_ULONG)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjectsInit ({what})"));

    let mut handles = vec![0 as CK_OBJECT_HANDLE; max_count];
    let mut count: CK_ULONG = 0;
    let rv = unsafe {
        ykcs11::C_FindObjects(h_session, handles.as_mut_ptr(), handles.len() as CK_ULONG, &mut count)
    };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjects ({what})"));
    assert!(
        (count as usize) < max_count,
        "{what}: found {count} objects, max_count={max_count} may have truncated results"
    );

    let rv = unsafe { ykcs11::C_FindObjectsFinal(h_session) };
    assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_FindObjectsFinal ({what})"));

    handles.truncate(count as usize);
    handles
}

#[test]
fn test_find_objects() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_find_objects: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    let slot_id = first_populated_slot();
    let session = open_session(slot_id);

    const ID: u8 = 1; // 9a (Authentication)
    let id_bytes = [ID];
    let keys = generate_ec_keys(session, &id_bytes, P256_EC_PARAMS);
    let (privkey, pubkey) = keys[0];

    login_user(session, CKR_OK as CK_RV);

    let mut id_template = [attr(CKA_ID, &id_bytes)];
    let found = find_objects(session, &mut id_template, 10, "by CKA_ID");

    let mut n_privkey = 0;
    let mut n_pubkey = 0;
    let mut n_cert = 0;
    let mut n_data = 0;
    for &handle in &found {
        let class_bytes = get_attribute(session, handle, CKA_CLASS, std::mem::size_of::<CK_ULONG>(), "CKA_CLASS");
        let class = CK_ULONG::from_ne_bytes(class_bytes.try_into().unwrap()) as u32;
        match class {
            CKO_PRIVATE_KEY => {
                n_privkey += 1;
                assert_eq!(handle, privkey, "wrong private key handle");
            }
            CKO_PUBLIC_KEY => {
                n_pubkey += 1;
                assert_eq!(handle, pubkey, "wrong public key handle");
            }
            CKO_CERTIFICATE => n_cert += 1,
            CKO_DATA => n_data += 1,
            other => panic!("unexpected CKA_CLASS {other:#x} among objects sharing CKA_ID={ID}"),
        }
    }
    assert_eq!(n_privkey, 1, "expected exactly one private key object");
    assert_eq!(n_pubkey, 1, "expected exactly one public key object");
    // Could be more than 1 certificate if the firmware version supports attestation
    assert!(n_cert >= 1, "expected at least one certificate object, found {n_cert}");
    assert!(n_data >= 1, "expected at least one data object, found {n_data}");

    let privkey_found = find_object_handle(session, CKO_PRIVATE_KEY, ID, "private key by class+id");
    assert_eq!(privkey_found, privkey, "wrong private key handle (class+id search)");

    let pubkey_found = find_object_handle(session, CKO_PUBLIC_KEY, ID, "public key by class+id");
    assert_eq!(pubkey_found, pubkey, "wrong public key handle (class+id search)");

    let cert_class = ulong_bytes(CKO_CERTIFICATE);
    let mut cert_template = [attr(CKA_ID, &id_bytes), attr(CKA_CLASS, &cert_class)];
    let certs = find_objects(session, &mut cert_template, 10, "certificates by class+id");
    assert!(!certs.is_empty(), "expected at least one certificate object (class+id search)");

    let data_class = ulong_bytes(CKO_DATA);
    let mut data_template = [attr(CKA_ID, &id_bytes), attr(CKA_CLASS, &data_class)];
    let data_objs = find_objects(session, &mut data_template, 10, "data objects by class+id");
    assert!(!data_objs.is_empty(), "expected at least one data object (class+id search)");

    logout(session, CKR_OK as CK_RV);
    close_session(session);
}
