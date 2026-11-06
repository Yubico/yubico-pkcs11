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
use crate::ec::{generate_ec_keys, ecdsa_sign};
use std::ptr;

fn session_info(session: CK_SESSION_HANDLE) -> CK_SESSION_INFO {
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = unsafe { ykcs11::C_GetSessionInfo(session, &mut info) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetSessionInfo");
    info
}

#[test]
fn test_session() {
    if !hardware_tests_enabled() {
        eprintln!("skipping hardware_session: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    let session = open_session(slot_id);
    let mut info: CK_SESSION_INFO = session_info(session);
    assert_eq!(
        info.state,
        CKS_RW_PUBLIC_SESSION as CK_STATE,
        "CK_SESSION_INFO.state"
    );
    assert_eq!(
        info.flags,
        (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
        "CK_SESSION_INFO.flags"
    );
    assert_eq!(info.ulDeviceError, 0, "CK_SESSION_INFO.ulDeviceError");

    let rv = unsafe { ykcs11::C_CloseSession(session) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession");

    // The handle must be rejected once closed.
    let rv = unsafe { ykcs11::C_GetSessionInfo(session, &mut info) };
    assert_eq!(
        rv,
        CKR_SESSION_HANDLE_INVALID as CK_RV,
        "C_GetSessionInfo after close: expected CKR_SESSION_HANDLE_INVALID, got rv={rv:#x}"
    );
}

/// `CKU_USER` and `CKU_SO` logins are mutually exclusive on a slot, and that holds across
/// every session open on the slot, not just the one that performed the login
#[test]
fn test_login() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_login: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();
    let session1: CK_SESSION_HANDLE = open_session(slot_id);

    // Login as USER and verify SO can't log in on top of it.
    login_user(session1, CKR_OK as CK_RV);
    login_so(session1, CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV);
    let rv = unsafe { ykcs11::C_Logout(session1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout(CKU_USER) session1");

    // Login as SO and verify USER can't log in on top of it.
    login_so(session1, CKR_OK as CK_RV);
    login_user(session1, CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV);

    // Open a second session and confirm it sees the same slot-wide SO login
    // state the first session set up.
    let session2: CK_SESSION_HANDLE = open_session(slot_id);
    let info: CK_SESSION_INFO = session_info(session2);
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE, "session2 state");

    let rv = unsafe { ykcs11::C_Logout(session1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout(CKU_SO) session1");

    let info: CK_SESSION_INFO = session_info(session1);
    assert_eq!(
        info.state,
        CKS_RW_PUBLIC_SESSION as CK_STATE,
        "session1 state after logout"
    );

    let info: CK_SESSION_INFO = session_info(session2);
    assert_eq!(
        info.state,
        CKS_RW_PUBLIC_SESSION as CK_STATE,
        "session2 state after logout"
    );

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

/// Generates two EC P-256 key pairs (PIV slots 9a/9c), then for each one logs in as
/// `CKU_USER` on `session1`, opens an extra session purely to confirm its
/// presence doesn't interfere, signs with that key on `session1`, and logs
/// back out. The test showcases that repeated login/logout cycling doesn't
/// disturb a signing operation already set up on another still-open
/// session.
#[test]
fn test_login_order() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_login_order: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();
    token_init(slot_id.clone());

    let h_session1: CK_SESSION_HANDLE = open_session(slot_id.clone());

    let keys = generate_ec_keys(h_session1, &[1, 2], P256_EC_PARAMS);

    let mut leaked_sessions = Vec::new();

    for (privkey, _) in keys.clone() {
        // A second session is opened on every iteration purely to confirm its mere presence
        // doesn't interfere with the sign operation on session1
        let h_session2: CK_SESSION_HANDLE = open_session(slot_id.clone());
        leaked_sessions.push(h_session2);

        ecdsa_sign(h_session1, privkey, None, 32);
    }

    // Clean up the generated keys under a fresh CKU_SO login.
    login_so(h_session1, CKR_OK as CK_RV);
    for key in keys {
        let rv = unsafe { ykcs11::C_DestroyObject(h_session1, key.0) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DestroyObject");
    }
    let rv = unsafe { ykcs11::C_Logout(h_session1) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout(CKU_SO)");

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

/// login state (`CKU_USER`/`CKU_SO`) lives on the slot, not the session, so
/// every session open on a slot observes the same state regardless of which
/// session performed the login or logout -- including a session opened
/// after the login already happened.
#[test]
fn test_multiple_sessions() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_multiple_sessions: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    // Open the first session as a public session (no logging in).
    let session1 = open_session(slot_id);
    let info: CK_SESSION_INFO = session_info(session1);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION as CK_STATE, "session1 state");

    // Open a second session and log in as USER on it. Both sessions
    // should then report CKS_RW_USER_FUNCTIONS
    let session2 = open_session(slot_id);
    login_user(session2, CKR_OK as CK_RV);
    let info: CK_SESSION_INFO = session_info(session2);
    assert_eq!(
        info.state,
        CKS_RW_USER_FUNCTIONS as CK_STATE,
        "session2 state after USER login"
    );
    let info: CK_SESSION_INFO = session_info(session1);
    assert_eq!(
        info.state,
        CKS_RW_USER_FUNCTIONS as CK_STATE,
        "session1 state after USER login on session2"
    );

    // Logout from session2 => both sessions go back to public.
    let rv = unsafe { ykcs11::C_Logout(session2) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_Logout(CKU_USER) session2");
    let info: CK_SESSION_INFO = session_info(session2);
    assert_eq!(
        info.state,
        CKS_RW_PUBLIC_SESSION as CK_STATE,
        "session2 state after logout"
    );
    let info: CK_SESSION_INFO = session_info(session1);
    assert_eq!(
        info.state,
        CKS_RW_PUBLIC_SESSION as CK_STATE,
        "session1 state after logout"
    );

    // Open a third session and log in as SO => all three sessions should
    // now report CKS_RW_SO_FUNCTIONS.
    let session3 = open_session(slot_id);
    login_so(session3, CKR_OK as CK_RV);
    for (session, name) in [(session3, "session3"), (session2, "session2"), (session1, "session1")] {
        let info: CK_SESSION_INFO = session_info(session);
        assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE, "{name} state after SO login");
    }

    // Close session2. Its handle becomes invalid.
    let rv = unsafe { ykcs11::C_CloseSession(session2) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseSession(session2)");
    let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    let rv = unsafe { ykcs11::C_GetSessionInfo(session2, &mut info) };
    assert_eq!(
        rv,
        CKR_SESSION_HANDLE_INVALID as CK_RV,
        "C_GetSessionInfo(session2) after close: rv={rv:#x}"
    );

    // Open a fourth session. It still observes the slot-wide SO login
    // state session1/session3 set up, even though it was opened after
    // session2 was closed.
    let session4 = open_session(slot_id);
    let info: CK_SESSION_INFO = session_info(session4);
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE, "session4 state");

    // A USER login attempt on the slot still fails while SO is logged in
    login_user(session4, CKR_USER_ANOTHER_ALREADY_LOGGED_IN as CK_RV);
    let info: CK_SESSION_INFO = session_info(session4);
    assert_eq!(info.state, CKS_RW_SO_FUNCTIONS as CK_STATE, "session4 state unchanged");

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");
}

/// a slot allows at most 16 concurrent sessions (`piv_slot::YKCS11_MAX_SESSIONS`).
/// The next `C_OpenSession` past that returns `CKR_SESSION_COUNT`, and
/// `C_CloseAllSessions` releases every one of them at once.
#[test]
fn test_max_multiple_sessions() {
    if !hardware_tests_enabled() {
        eprintln!("skipping test_max_multiple_sessions: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    const MAX_SESSIONS: usize = 16;
    let mut sessions = Vec::with_capacity(MAX_SESSIONS);
    for _ in 0..MAX_SESSIONS {
        let session = open_session(slot_id);
        session_info(session);
        sessions.push(session);
    }

    // The slot is now at capacity => one more C_OpenSession must fail
    let mut extra_session: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        ykcs11::C_OpenSession(
            slot_id,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
            ptr::null_mut(),
            None,
            &mut extra_session,
        )
    };
    assert_eq!(
        rv,
        CKR_SESSION_COUNT as CK_RV,
        "C_OpenSession past the session limit: rv={rv:#x}"
    );

    let rv = unsafe { ykcs11::C_CloseAllSessions(slot_id) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_CloseAllSessions");

    for session in sessions {
        let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { ykcs11::C_GetSessionInfo(session, &mut info) };
        assert_eq!(
            rv,
            CKR_SESSION_HANDLE_INVALID as CK_RV,
            "C_GetSessionInfo after C_CloseAllSessions: rv={rv:#x}"
        );
    }
}
