// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! Hardware-gated integration tests for the YubiKey PIV PKCS#11 module —
//! the Rust equivalent of yubico-piv-tool's `ykcs11/tests/ykcs11_tests.c`
//! (that harness has no single `token_init()` either; `reset.sh` blocks the
//! PIN/PUK and calls the CLI's `-areset` before the test binary runs). This
//! crate plays the same role for `ykcs11`, calling the real C ABI
//! (`pub use dispatch::*` at the crate root) exactly as `pkcs11-tool` or any
//! other PKCS#11 consumer would — no internal shortcuts.
//!
//! One test area per file in this directory, for readability -- but all
//! still compiled into this single `hardware_tests` test binary (Cargo
//! auto-discovers `tests/hardware_tests/main.rs` as a test target named
//! `hardware_tests`, same as a flat `tests/hardware_tests.rs` would be; the
//! `mod` declarations below then resolve to sibling files in this same
//! directory). That means the one-command invocation below still runs every
//! hardware test together, with no need to name each test file individually,
//! and `common::HARDWARE_LOCK` still serializes them all correctly since
//! they share one process.
//!
//! Covers `C_GetTokenInfo` (`token_info.rs`); `C_GetMechanismList`/
//! `C_GetMechanismInfo` (`mechanisms.rs`); importing ML-DSA (`ml_dsa.rs`) and
//! ML-KEM (`ml_kem.rs`) private keys (`C_CreateObject`); and ML-KEM
//! encapsulate/decapsulate (`C_EncapsulateKey`/`C_DecapsulateKey`, reached
//! via `C_GetInterfaceList`/`C_GetInterface` -- see `dispatch.rs`'s own doc
//! comment on `G_INTERFACES` for why those aren't reachable through
//! `C_GetFunctionList`). Being built up incrementally toward parity with
//! `ykcs11_tests.c`, then extended with more PQC coverage.
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
//! "wipe and reinitialize" PKCS#11 call) — every PIV key and certificate on
//! it is permanently destroyed. Only ever run this against a dedicated
//! test/development YubiKey, never one holding keys you care about.
//!
//! `cargo test` runs every test in a binary concurrently by default, and two
//! tests racing to reset/open a session on the same physical device would
//! not behave sanely -- every `#[test]` fn across every module below
//! acquires `common::HARDWARE_LOCK` first and holds it for its whole body,
//! serializing all hardware access onto one thread at a time regardless of
//! how `cargo test` schedules them.

mod util;
mod mechanisms;
mod ml_dsa;
mod ml_kem;
mod token_info;
