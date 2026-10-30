//Created by Salty on 10/29/26.

#include <CoreFoundation/CoreFoundation.h>

#ifndef AMTWEAK_H
#define AMTWEAK_H

#ifdef __cplusplus
extern "C" {
#endif
    
struct __AMTweak {
    CFStringRef tweak_library_path;
    CFStringRef tweak_name;
    CFArrayRef  blacklisted_apps;
    CFArrayRef  whitelisted_apps;
};
typedef struct __AMTweak *AMTweakRef;

AMTweakRef AMTweakCreateWithPath(CFStringRef path);
bool AMTweakShouldInjectToApplication(AMTweakRef tweak, CFStringRef application);
void AMTweakRelease(AMTweakRef tweak);

#ifdef __cplusplus
}
#endif

#endif /* AMTWEAK_H */
