//Created by Salty on 10/31/26.

#ifndef AMBLACKLIST_H
#define AMBLACKLIST_H

#include <CoreFoundation/CFURL.h>
#include "AMBase.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct __AMBlacklist;
typedef struct __AMBlacklist *AMBlacklistRef;

#define AM_GLOBAL_BLACKLIST_PATH "/private/var/ammonia/core/ammonia_global.blacklist"

/// Creates and assigns an AMBlacklistRef to the out parameter. Error is returned if creation is not possible, the input was invalid, or, returns AMError.AMSuccess if all checks succeed.
AMError AMBlacklistCreateWithBlacklistAtURL(CFURLRef URL, AMBlacklistRef AM_RETURNS_RETAINED *out);

/// Returns the AMTypeID for AMBlacklist objects.
AMTypeID AMBlacklistGetTypeID(void);

/// Returns whether or not the executable is blacklisted by the file. This function explicitly ignores the intermediate path components of the provided CFURL, and checks only the last path component of the provided CFURL.
bool AMBlacklistGetExecutableIsBlacklisted(AMBlacklistRef obj, CFURLRef executable_URL);

/// Returns whether or not the full path is blacklisted by the file.
bool AMBlacklistGetFullPathIsBlacklisted(AMBlacklistRef obj, CFStringRef path);

/// Returns the count of items inside the blacklist.
CFIndex AMBlacklistGetCount(AMBlacklistRef obj);

/// Returns whether or not all executables are blacklisted. This can be due to a few factors, the input blacklist is NULL (meaning no blacklist existed) or the blacklist contained a \"\*\" character as an enty on a line.
bool AMBlacklistGetAllExecutablesAreBlacklisted(AMBlacklistRef obj);

/// Creates and assigns an AMBlacklistRef to the out parameter. Error is return if creation is not possible. The blacklist is read from the global location (/private/var/ammonia/core/ammonia\_global.blacklist).
AMError AMBlacklistCreateFromGlobalBlacklist(AMBlacklistRef AM_RETURNS_RETAINED *out);

#ifdef __cplusplus
}
#endif

#endif /* AMBLACKLIST_H */
