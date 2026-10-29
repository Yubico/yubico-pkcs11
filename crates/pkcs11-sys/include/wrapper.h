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


#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* Yubico's own extension to the OASIS headers (see pkcs11y.h) -- the
 * Cryptoki version every "legacy" (pre-3.0) CK_FUNCTION_LIST still
 * conforms to. Duplicated here rather than #include-ing pkcs11y.h
 * wholesale, which would redefine CK_PTR/CK_BOOL/etc. below (with a
 * different CK_BOOL body: `bool` vs. `_Bool`) and risk a preprocessor
 * conflict -- same reason this file re-declares those macros by hand
 * instead of pulling them in from pkcs11y.h too. */
#define CRYPTOKI_LEGACY_VERSION_MAJOR 2
#define CRYPTOKI_LEGACY_VERSION_MINOR 40

#define CK_PTR *
#define CK_BOOL _Bool
#define CK_HANDLE void *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define CK_DEFINE_FUNCTION(returnType, name) returnType name

/* Matches the real convention (see e.g. yubico-piv-tool's pkcs11y.h):
 * Cryptoki structures are 1-byte packed on Windows only. CK_ULONG is 4
 * bytes there (LLP64) vs. 8 on Unix (LP64), and every Windows PKCS#11
 * implementation/consumer pins the layout with this pragma to stay
 * ABI-stable regardless of the caller's own default packing settings. */
#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif
#include "pkcs11t.h"
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif
