/*
 * Copyright (c) 2026 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
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
