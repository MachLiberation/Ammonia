//Created by Salty on 10/29/26.

#ifndef AMTWEAK_H
#define AMTWEAK_H

#include <CoreFoundation/CoreFoundation.h>
#include "AMBase.h"
#include "AMWhitelist.h"
#include "AMBlacklist.h"

#ifdef __cplusplus
extern "C" {
#endif
    
struct __AMTweak;
typedef struct __AMTweak *AMTweakRef;

/// Creates a tweak object by passing a path into the function. The immediate directory is scanned for both whitelist and blacklist files matching the given tweak's name following a %s.dylib.whitelist/%s.dylib.blacklist convention.
AM_RETURNS_RETAINED AMTweakRef AMTweakCreateWithPath(CFStringRef path);

/// Singular lookup to answer whether the application/executible should be injected with the tweak library. Internal logic checks the loaded tweak object's blacklist/whitelist and compares against a known baseline of "should not be" injected executible paths.
bool AMTweakShouldInjectToApplication(AMTweakRef tweak, CFStringRef application_full_path);

/// Returns the AMTypeID for AMTweak objects.
AMTypeID AMTweakGetTypeID(void);

/// Does the injection logic.
bool AMTweakInjectionComparator(CFStringRef path, AMWhitelistRef wl, AMBlacklistRef bl);

#ifdef __cplusplus
}
#endif

#endif /* AMTWEAK_H */
