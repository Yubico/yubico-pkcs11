/* Wrapper header for bindgen — includes all PKCS#11 types */

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

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
