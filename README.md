# yubico-pkcs11

A unified Rust workspace implementing PKCS#11 modules for both **YubiHSM 2** and **YubiKey PIV**.

## Structure

```
crates/
├── pkcs11-sys/     Raw PKCS#11 FFI bindings generated from OASIS 3.1 headers
├── pkcs11-common/     Shared PKCS#11 types, session state, attribute helpers
├── yubihsm-pkcs11/   YubiHSM 2 PKCS#11 module (uses yubihsmrs)
└── ykcs11/            YubiKey PIV PKCS#11 module (uses yubikit)
```

## Building

```bash
# Build everything (both modules + common library)
cargo build --release

# Build only the YubiKey PIV module
cargo build --release -p ykcs11

# Build only the YubiHSM module
cargo build --release -p yubihsm-pkcs11

# Build only the shared library (no .so/.dll output, just the rlib)
cargo build --release -p pkcs11-common
```

This produces:
- `target/release/libyubihsm_pkcs11.so` (+ `.a`) — YubiHSM module
- `target/release/libykcs11.so` (+ `.a`) — YubiKey PIV module

On Windows: `.dll` + `.lib`; on macOS: `.dylib` + `.a`.

## Versioning

Each module has its own version in its `Cargo.toml`:
- `yubihsm-pkcs11` → version `0.1.0` (PKCS#11 3.1)
- `ykcs11` → version `0.1.0` (PKCS#11 3.0)

## Dependencies

- **yubihsm-pkcs11** depends on [`yubihsmrs`](https://github.com/Yubico/yubihsmrs)
- **ykcs11** depends on [`yubikit`](https://github.com/Yubico/yubikey-manager/tree/experiment/rust) with the `hardware` feature

`ykcs11` is otherwise self-contained (`yubikit` is pure Rust). `yubihsm-pkcs11`
is not: `yubihsmrs` is a binding to the native `libyubihsm` C library, so the
built module has a *runtime* shared-library dependency on it, separate from
however it was located at build time:

```bash
# Build time: point libyubihsm-sys at a libyubihsm build/install (skips
# pkg-config). See yubihsmrs/libyubihsm-sys/build.rs for the alternative:
# a system-wide install discoverable via pkg-config, with no env vars needed.
export YUBIHSM_LIB_DIR=/path/to/yubihsm-shell/build/lib
cargo build --release -p yubihsm-pkcs11

# Run time: the dynamic loader doesn't read YUBIHSM_LIB_DIR — point it at
# the same directory explicitly, or install libyubihsm system-wide and run
# ldconfig instead.
LD_LIBRARY_PATH=/path/to/yubihsm-shell/build/lib pkcs11-tool --module target/release/libyubihsm_pkcs11.so -L
```

## Usage

```bash
# YubiHSM
export YUBIHSM_PKCS11_CONF=/path/to/yubihsm_pkcs11.conf
pkcs11-tool --module target/release/libyubihsm_pkcs11.so -L

# YubiKey PIV
pkcs11-tool --module target/release/libykcs11.so -L
```

## License

- `pkcs11-common` and `yubihsm-pkcs11`: Apache-2.0
- `ykcs11`: BSD-2-Clause