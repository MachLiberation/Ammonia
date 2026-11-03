//Created by Salty on 10/31/26.

#include "AMBase.h"
#include "_AMBase.h"
#include <pthread.h>
#include <stdlib.h>

#define MAX_CLASS_COUNT 128
static const AMClass *gClasses[MAX_CLASS_COUNT];
static uint32_t gClassCount = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

AMTypeID AMRegisterClass(const AMClass *cls){
    pthread_mutex_lock(&gLock);
    AMTypeID type_id = AMTypeIDInvalid;
    if (gClassCount < MAX_CLASS_COUNT){
        type_id = gClassCount;
        gClasses[gClassCount++] = cls;
    }
    pthread_mutex_unlock(&gLock);
    return type_id;
}

AMTypeRef AMCreateInstance(AMTypeID type_id, size_t size){
    if (size < sizeof(AMBase)) return NULL;

    pthread_mutex_lock(&gLock);
    const AMClass *cls = (type_id < gClassCount) ? gClasses[type_id] : NULL;
    pthread_mutex_unlock(&gLock);
    if (!cls) return NULL;

    AMBase *base = calloc(1, size);
    if (!base) return NULL;
    base->cls = cls;
    base->type_id = type_id;
    atomic_init(&base->retain_count, 1);
    return base;
}

AMTypeRef AMRetain(AMTypeRef obj){
    AMBase *base = (AMBase *)obj;
    atomic_fetch_add_explicit(&base->retain_count, 1, memory_order_relaxed);
    return obj;
}

void AMRelease(AMTypeRef obj){
    AMBase *base = (AMBase *)obj;
    if (atomic_fetch_sub_explicit(&base->retain_count, 1, memory_order_release) == 1) {
        atomic_thread_fence(memory_order_acquire);
        if (base->cls->destructor) base->cls->destructor(obj);
        free(base);
    }
}

AMTypeID AMGetTypeID(AMTypeRef obj){
    return ((const AMBase *)obj)->type_id;
}
