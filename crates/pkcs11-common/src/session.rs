/*
 * Copyright (c) 2026 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
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