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

use std::env;
use std::path::PathBuf;

fn main() {
    let include_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("include");

    let bindings = bindgen::Builder::default()
        .header(include_dir.join("wrapper.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", include_dir.display()))
        .allowlist_type("CK_.*")
        .allowlist_var("CK.*")
        .allowlist_var("CKR_.*")
        .allowlist_var("CKF_.*")
        .allowlist_var("CKS_.*")
        .allowlist_var("CKU_.*")
        .allowlist_var("CKM_.*")
        .allowlist_var("CKA_.*")
        .allowlist_var("CKO_.*")
        .allowlist_var("CKK_.*")
        .allowlist_var("CKP_.*")
        .allowlist_var("CKC_.*")
        .allowlist_var("CRYPTOKI_.*")
        .blocklist_type("CK_FUNCTION_LIST.*")
        .blocklist_type("CK_FUNCTION_LIST_PTR.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .prepend_enum_name(false)
        .generate_comments(true)
        .generate()
        .expect("Unable to generate PKCS#11 bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11_bindings.rs"))
        .expect("Couldn't write bindings");
}