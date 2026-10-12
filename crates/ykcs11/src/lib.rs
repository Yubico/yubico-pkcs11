// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

#![allow(non_snake_case)]
#![allow(unused_variables)]

extern crate pkcs11_common;
extern crate yubikit;

mod backend;
mod create_object;
mod decrypt;
mod derive;
mod destroy_object;
mod discovery;
mod encrypt;
mod generate;
mod dispatch;
mod mechanisms;
mod objects;
mod piv_slot;
mod sign;
mod template;
mod verify;

pub use dispatch::*;