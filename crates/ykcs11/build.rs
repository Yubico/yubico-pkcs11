fn main() {
    // Without this, the dylib's install name is an absolute path into the
    // build directory (target/release/build/ykcs11-<hash>/out/...).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libykcs11.dylib");
    }
}