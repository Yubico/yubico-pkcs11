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


use digest::DynDigest;
use pkcs11_sys::*;

/// One in-progress digest operation.
pub struct DigestOp {
    hasher: Box<dyn DynDigest + Send>,
}

impl DigestOp {

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

    /// The digest's fixed output length calculated from the hash algorithm
    pub fn output_len(&self) -> usize {
        self.hasher.output_size()
    }

    pub fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().into_vec()
    }
}
