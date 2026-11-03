//Created by Salty on 10/31/26.

#ifndef AMBASE_H
#define AMBASE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __has_attribute(cf_returns_retained)
#define AM_RETURNS_RETAINED __attribute__((cf_returns_retained))
#else
#define AM_RETURNS_RETAINED
#endif

typedef enum {
    AMSuccess = 0,
    AMErrorURLDoesNotMatchExpectedExtension = 1,
    AMErrorURLIsNULL = 2,
    AMErrorURLDoesNotHaveExtension = 3,
    AMErrorCouldNotParseFile = 4,
    AMErrorCouldNotAllocateBaseClass = 5,
    AMErrorOutParamIsNULL = 6,
    AMErrorCouldNotCreateInternalProperty = 7,
    AMErrorObjectInputParameterIsNULL = 8
} AMError;

typedef const void *AMTypeRef;
typedef uint64_t AMTypeID;

#define AMTypeIDInvalid ((AMTypeID)UINT64_MAX)

/// Increments retain count.
AMTypeRef AMRetain(AMTypeRef obj);

/// Decrements retain count. 0 calls destructor then free().
void AMRelease(AMTypeRef obj);

/// Returns type\_id value of AMClass object.
AMTypeID AMGetTypeID(AMTypeRef obj);

#ifdef __cplusplus
}
#endif

#endif /* AMBASE_H */
