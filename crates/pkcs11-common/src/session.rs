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