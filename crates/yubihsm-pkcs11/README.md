# yubihsm-pkcs11

An implementation of PKCS#11 API for **YubiHSM 2**.

This is a work in progress and is currently not supported as part of the official YubiHSM SDK


## Building

```bash
# Build only the YubiHSM module
cargo build -p yubihsm-pkcs11
```

This produces `target/debug/libyubihsm_pkcs11.{so/dylib/dll}` (+ `.a`) — YubiHSM module.
On Windows: `.dll` + `.lib`; on macOS: `.dylib` + `.a`.

## Dependencies

Depends on [`yubihsmrs`](https://github.com/Yubico/yubihsmrs)
- **ykcs11** depends on [`yubikit`](https://github.com/Yubico/yubikey-manager/tree/6.0.0-beta.0) with the `hardware` feature

`yubihsm-pkcs11` is not self-contained. `yubihsmrs` is a binding to the native `libyubihsm` C library, so the
built module has a *runtime* shared-library dependency on it, separate from
however it was located at build time:

```bash
# Build time: Set YUBIHSM_LIB_DIR to the directory containing libyubihsm
export YUBIHSM_LIB_DIR=/path/to/yubihsm-shell/build/lib
cargo build -p yubihsm-pkcs11

# Run time: Set LD_LIBRARY_PATH to the directory containing libyubihsm
export LD_LIBRARY_PATH=/path/to/yubihsm-shell/build/lib
```

## Usage

For example with `pkcs11-tool`:

```bash
export YUBIHSM_PKCS11_CONF=/path/to/yubihsm_pkcs11.conf
pkcs11-tool --module path/to/libyubihsm_pkcs11.so --show-info
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