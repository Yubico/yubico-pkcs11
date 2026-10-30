# ykcs11

An implementation of PKCS#11 API for **YubiKey PIV**.

This is a work in progress and is currently not supported as an official Yubico software.

## Building

```bash
# Build only the YubiKey PIV module
cargo build -p ykcs11
```

This produces `target/debug/libykcs11.{so/dylib/dll}` (+ `.a`).
On Windows: `.dll` + `.lib`; on macOS: `.dylib` + `.a`.


## Dependencies

Depends on [`yubikit`](https://github.com/Yubico/yubikey-manager/tree/6.0.0-beta.0) with the `hardware` feature.
`ykcs11` is otherwise self-contained (`yubikit` is pure Rust).

## Usage

For example with `pkcs11-tool`:

```bash
pkcs11-tool --module path/to/libykcs11.so --show-info
```

## License

In general the project is covered by the Apache 2.0 license.  The
header files `crates/ykcs11-sys/include/pkcs11*.h` have additional copyright and licensing
information, please see them for more information.

....

    Copyright 2026 Yubico AB

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
....