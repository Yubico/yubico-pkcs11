fn main() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("YUBIHSM_STATIC").is_ok() {
            if let Ok(lib_dir) = std::env::var("YUBIHSM_LIB_DIR") {
                let lib_name = std::env::var("YUBIHSM_LIB_NAME")
                    .unwrap_or_else(|_| "yubihsm".to_string());
                let lib_path = std::path::Path::new(&lib_dir)
                    .join(format!("lib{}.a", lib_name));
                println!("cargo:rustc-link-arg=-Wl,--push-state,--whole-archive");
                println!("cargo:rustc-link-arg={}", lib_path.display());
                println!("cargo:rustc-link-arg=-Wl,--pop-state");
                // libyubihsm's curl and usb backends need these
                println!("cargo:rustc-link-lib=dylib=curl");
                println!("cargo:rustc-link-lib=dylib=usb-1.0");
            }
        } else {
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Only needed when linking against static libyubihsm.a
        // Set YUBIHSM_STATIC=1 in CI release builds
        println!("cargo:rerun-if-env-changed=YUBIHSM_STATIC");
        if std::env::var("YUBIHSM_STATIC").is_ok() {
            println!("cargo:rustc-link-lib=static=curl");
            println!("cargo:rustc-link-lib=static=usb-1.0");

            // System frameworks needed by SecureTransport-backed curl
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=SystemConfiguration");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");

            // System frameworks needed by libusb
            println!("cargo:rustc-link-lib=framework=IOKit");

            // Tell the linker where to find the libraries at build time
            // println!("cargo:rerun-if-env-changed=BREW_LIB");
            println!("cargo:rerun-if-env-changed=CURL_LIB_DIR");
            println!("cargo:rerun-if-env-changed=LIBUSB_LIB_DIR");
            if let Ok(curl_lib_dir) = std::env::var("CURL_LIB_DIR") {
                println!("cargo:rustc-link-search={}", curl_lib_dir);
            }
            if let Ok(libusb_lib_dir) = std::env::var("LIBUSB_LIB_DIR") {
                println!("cargo:rustc-link-search={}", libusb_lib_dir);
            }
        } else {
            println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Transitive dependencies of static yubihsm.lib
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=winusb");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=setupapi");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
    }
}
