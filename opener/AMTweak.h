//Created by Salty on 10/29/26.

#include <CoreFoundation/CoreFoundation.h>

#ifndef AMTWEAK_H
#define AMTWEAK_H

#ifdef __cplusplus
extern "C" {
#endif
    
struct __AMTweak;
typedef struct __AMTweak *AMTweakRef;

/// Creates a tweak object by passing a path into the function. The immediate directory is scanned for both whitelist and blacklist files matching the given tweak's name following a %s.dylib.whitelist/%s.dylib.blacklist convention.
CF_RETURNS_RETAINED
AMTweakRef AMTweakCreateWithPath(CFStringRef path);

/// Singular lookup to answer whether the application/executible should be injected with the tweak library. Internal logic checks the loaded tweak object's blacklist/whitelist and compares against a known baseline of "should not be" injected executible paths.
bool AMTweakShouldInjectToApplication(AMTweakRef tweak, CFStringRef application);

/// Deallocates the internal structure and frees the memory of the tweak object. Can pass NULL but dereferencing an already-deallocated object will cause a crash.
void AMTweakRelease(AMTweakRef tweak);

#ifdef __cplusplus
}
#endif

#endif /* AMTWEAK_H */
