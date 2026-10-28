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


use digest::DynDigest;
use pkcs11_sys::*;

/// One in-progress digest operation. `Box<dyn DynDigest + Send>` avoids a
/// hand-rolled enum over the 4 supported hash algorithms — `update`/
/// `output_size`/`finalize` all dispatch through the trait object.
pub struct DigestOp {
    hasher: Box<dyn DynDigest + Send>,
}

impl DigestOp {
    /// `None` (via `Err`) for any mechanism besides the 4 both C references
    /// support — matches `digest_mechanism_init`'s `default: return
    /// CKR_MECHANISM_INVALID` (mechanisms.c:620) and yubihsm_pkcs11's
    /// `check_digest_mechanism` (util_pkcs11.c:2398-2410), which recognize
    /// exactly the same 4.
    pub fn new(mechanism: CK_MECHANISM_TYPE) -> Result<Self, CK_RV> {
        let hasher: Box<dyn DynDigest + Send> = match mechanism as u32 {
            CKM_SHA_1 => Box::new(sha1::Sha1::default()),
            CKM_SHA256 => Box::new(sha2::Sha256::default()),
            CKM_SHA384 => Box::new(sha2::Sha384::default()),
            CKM_SHA512 => Box::new(sha2::Sha512::default()),
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        Ok(Self { hasher })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// The digest's fixed output length — known as soon as the mechanism is
    /// picked, before any data is hashed (matches `session->op_info.out_len`
    /// being set in `digest_mechanism_init`, used by `C_Digest`/
    /// `C_DigestFinal` to answer a length-only query with `pDigest == NULL`
    /// without needing to finalize anything).
    pub fn output_len(&self) -> usize {
        self.hasher.output_size()
    }

    pub fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().into_vec()
    }
}
