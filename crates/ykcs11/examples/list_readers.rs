// Copyright 2026 Yubico AB

//! Standalone diagnostic: calls yubikit's PC/SC reader enumeration in
//! isolation, with no pkcs11-tool, no dispatch/Engine code, and no C ABI
//! boundary involved. Used to determine whether a crash seen when loading
//! ykcs11.dll into pkcs11-tool originates inside yubikit's PC/SC layer.
//!
//! Run with: cargo run -p ykcs11 --example list_readers

fn main() {
    println!("Calling yubikit::platform::pcsc::list_readers_with_state() ...");
    match yubikit::platform::pcsc::list_readers_with_state() {
        Ok(readers) => {
            println!("Ok, {} reader(s):", readers.len());
            for (name, present) in readers {
                println!("  {name} (card present: {present})");
            }
        }
        Err(e) => {
            println!("Err: {e}");
        }
    }
    println!("Returned normally, no crash.");
}
