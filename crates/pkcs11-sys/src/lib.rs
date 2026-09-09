//! Raw PKCS#11 type bindings generated from OASIS 3.1 C headers.
//!
//! This crate provides the `CK_*` types, constants, and struct definitions
//! exactly as they appear in the C specification.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/pkcs11_bindings.rs"));

// Bindgen can't parse the macro-inclusion struct definition, so we define it manually.
pub mod function_list;
pub use function_list::*;