//! Common session state types shared between both modules.

use pkcs11_sys::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginState {
    Public,
    User,
    SO,
}

/// Compute CK_STATE from login state and session flags.
pub fn compute_state(login: LoginState, flags: CK_FLAGS) -> CK_STATE {
    let is_rw = (flags & CKF_RW_SESSION as CK_FLAGS) != 0;
    match (login, is_rw) {
        (LoginState::Public, false) => CKS_RO_PUBLIC_SESSION.into(),
        (LoginState::Public, true) => CKS_RW_PUBLIC_SESSION.into(),
        (LoginState::User, false) => CKS_RO_USER_FUNCTIONS.into(),
        (LoginState::User, true) => CKS_RW_USER_FUNCTIONS.into(),
        (LoginState::SO, _) => CKS_RW_SO_FUNCTIONS.into(),
    }
}