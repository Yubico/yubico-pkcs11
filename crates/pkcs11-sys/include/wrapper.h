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

#include "pkcs11t.h"