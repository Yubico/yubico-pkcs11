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

fn expected_mechanisms(firmware: (u8, u8)) -> Vec<(CK_MECHANISM_TYPE, CK_ULONG, CK_ULONG, CK_FLAGS)> {
    let rsa_min = if firmware >= (6, 0) {
        2048
    } else {
        1024
    };

    let rsa_max = if firmware >= (5, 7) {
        4096
    } else {
        2048
    };

    let mut mechs = vec![
        (CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS),
        (CKM_RSA_PKCS as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS),
        (CKM_RSA_X_509 as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_SHA_1 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA256 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA384 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA512 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
    ];

    if firmware >= (5, 4) {
        mechs.push(
        (CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         255, 255, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
        mechs.push (
        (CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         255, 255, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
        mechs.push(
        (CKM_EDDSA as CK_MECHANISM_TYPE, 255, 255, (CKF_HW | CKF_SIGN | CKF_VERIFY |  CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
    }

    if firmware >= (6, 0) {
        mechs.push((CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS));
        mechs.push((CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS));
        mechs.push((CKM_ML_KEM as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_ENCAPSULATE | CKF_DECAPSULATE) as CK_FLAGS));
        mechs.push((CKM_ML_DSA as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS));
    }
    mechs
}

#[test]
fn test_token_info() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_token_info: set {RUN_ENV_VAR}=1 to run \
             (destructive -- see this crate's module doc comment)"
        );
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    // No session is opened before calling C_GetTokenInfo, so ulSessionCount/ulRwSessionCount
    // below are expected to be exactly 0.
    let info = token_info(slot_id);
    assert_prefix(&info.label, b"YubiKey PIV", "CK_TOKEN_INFO.label");
    assert_prefix(&info.model, b"YubiKey", "CK_TOKEN_INFO.model");

    let expected_flags = (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
        as CK_FLAGS;
    assert_eq!(info.flags, expected_flags, "CK_TOKEN_INFO.flags");

    assert_eq!(info.ulMaxSessionCount, 16, "ulMaxSessionCount");
    assert_eq!(info.ulSessionCount, 0, "ulSessionCount");
    assert_eq!(info.ulMaxRwSessionCount, 16, "ulMaxRwSessionCount");
    assert_eq!(info.ulRwSessionCount, 0, "ulRwSessionCount");

    assert_eq!(info.ulMinPinLen, 6, "ulMinPinLen");
    assert_eq!(info.ulMaxPinLen, 64, "ulMaxPinLen");

    let unavailable = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
    assert_eq!(info.ulTotalPublicMemory, unavailable, "ulTotalPublicMemory");
    assert_eq!(info.ulFreePublicMemory, unavailable, "ulFreePublicMemory");
    assert_eq!(info.ulTotalPrivateMemory, unavailable, "ulTotalPrivateMemory");
    assert_eq!(info.ulFreePrivateMemory, unavailable, "ulFreePrivateMemory");

    assert_eq!(info.hardwareVersion.major, 1, "hardwareVersion.major");
    assert_eq!(info.hardwareVersion.minor, 0, "hardwareVersion.minor");

    assert_eq!(info.utcTime, [b' '; 16], "CK_TOKEN_INFO.utcTime");

    eprintln!(
        "detected firmware {}.{}",
        info.firmwareVersion.major, info.firmwareVersion.minor
    );
}

#[test]
fn test_mechanism_list() {
    if !hardware_tests_enabled() {
        eprintln!("skipping hardware_mechanism_list_and_info: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    // Matches ykcs11_tests.c's ed25519_supported gate (firmware >= 5.7):
    // RSA key sizes above 2048 bits need firmware 5.7+ (backend.rs's own
    // mechanism_info()).
    let info = token_info(slot_id);
    let expected = expected_mechanisms((info.firmwareVersion.major, info.firmwareVersion.minor));

    let mut count: CK_ULONG = 0;
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetMechanismList (count)");
    assert_eq!(count as usize, expected.len(), "unexpected mechanism count");

    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, mechs.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetMechanismList (fill)");

    // Order isn't part of the PKCS#11 contract for C_GetMechanismList --
    // unlike ykcs11_tests.c's memcmp (which only works because it controls
    // the array layout on both sides), compare as sets.
    let mut mechs_sorted = mechs.clone();
    mechs_sorted.sort();
    let mut expected_types: Vec<CK_MECHANISM_TYPE> = expected.iter().map(|e| e.0).collect();
    expected_types.sort();
    assert_eq!(mechs_sorted, expected_types, "mechanism set mismatch");

    for (mechanism, min, max, flags) in expected {
        let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { ykcs11::C_GetMechanismInfo(slot_id, mechanism, &mut mech_info) };
        assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_GetMechanismInfo(0x{mechanism:x})"));
        assert_eq!(mech_info.ulMinKeySize, min, "0x{mechanism:x}: ulMinKeySize");
        assert_eq!(mech_info.ulMaxKeySize, max, "0x{mechanism:x}: ulMaxKeySize");
        assert_eq!(mech_info.flags, flags, "0x{mechanism:x}: flags");
    }
}