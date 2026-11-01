//Created by Salty on 10/31/26.

#ifndef _AMBASE_H
#define _AMBASE_H

#include "AMBase.h"
#include <stdatomic.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *name;
    void (*destructor)(AMTypeRef);
} AMClass;

typedef struct {
    const AMClass *cls;
    atomic_uint_fast32_t retain_count;
    AMTypeID type_id;
} AMBase;

AMTypeID AMRegisterClass(const AMClass *cls);

AM_RETURNS_RETAINED
AMTypeRef AMCreateInstance(AMTypeID type_id, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _AMBASE_H */
