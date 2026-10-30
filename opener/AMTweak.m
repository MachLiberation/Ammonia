//Created by Salty on 10/29/26.

#include "AMTweak.h"

AMTweakRef AMTweakCreate(void){
    struct __AMTweak *ref =
        ((struct __AMTweak *)malloc(sizeof(*ref)));
    
    if (ref == NULL)
        return NULL;
    
    ref->blacklisted_apps = NULL;
    ref->tweak_library_path = NULL;
    ref->tweak_name = NULL;
    ref->whitelisted_apps = NULL;
    
    return ref;
}

AMTweakRef AMTweakCreateWithPath(CFStringRef path){
    AMTweakRef ref = AMTweakCreate();
    
    if (ref == NULL || path == NULL)
        return NULL;
    
    //Do setup here with path entry
    
    return ref;
}

bool AMTweakShouldInjectToApplication(AMTweakRef tweak,
                                      CFStringRef application){
    
    
    return false;
}

void AMTweakRelease(AMTweakRef tweak){
    if (tweak == NULL)
        return;
    
    if (tweak->blacklisted_apps != NULL)
        CFRelease(tweak->blacklisted_apps);
    
    if (tweak->whitelisted_apps != NULL)
        CFRelease(tweak->whitelisted_apps);
    
    if (tweak->tweak_name != NULL)
        CFRelease(tweak->tweak_name);
    
    if (tweak->tweak_library_path != NULL)
        CFRelease(tweak->tweak_library_path);
    
    free((void *)tweak);
}
