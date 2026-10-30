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


// Yubico's own extension to the OASIS headers. Currently relevant only for ykcs11

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#define CRYPTOKI_LEGACY_VERSION_MAJOR 2
#define CRYPTOKI_LEGACY_VERSION_MINOR 40

#define CK_PTR *
#define CK_BOOL _Bool
#define CK_HANDLE void *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define CK_DEFINE_FUNCTION(returnType, name) returnType name

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif
#include "pkcs11t.h"
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif
