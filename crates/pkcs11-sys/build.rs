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