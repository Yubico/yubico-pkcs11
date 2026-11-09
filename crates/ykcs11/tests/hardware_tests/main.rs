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

//! Hardware-gated integration tests for the YubiKey PIV PKCS#11 module
//!
//! # Running
//!
//! These tests require a real YubiKey plugged in and are destructive (they
//! wipe the PIV application). They do **nothing** — no PC/SC access at all —
//! unless explicitly opted into:
//!
//! ```sh
//! YKCS11_HW_TESTS=1 cargo test -p ykcs11 --test hardware_tests
//! ```
//!
//! # !!! WARNING !!!
//!
//! Running with `YKCS11_HW_TESTS=1` resets the PIV application on every
//! YubiKey `C_GetSlotList` reports as present (via `C_InitToken`, the real
//! "wipe and reinitialize" PKCS#11 call). Every PIV key and certificate on
//! it is permanently destroyed. Only ever run this against a dedicated
//! test/development YubiKey, never one holding keys you care about.
//!
//! `cargo test` runs every test in a binary concurrently by default, and two
//! tests racing to reset/open a session on the same physical device would
//! not behave sanely. Every `#[test]` fn across every module below
//! acquires `common::HARDWARE_LOCK` first and holds it for its whole body,
//! serializing all hardware access onto one thread at a time regardless of
//! how `cargo test` schedules them.

mod util;
// mod ml_dsa;
// mod ml_kem;
mod digest;
mod ec;
mod rsa;
mod session;
mod token_info;
