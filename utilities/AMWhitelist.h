//Created by Salty on 10/31/26.

#ifndef AMWHITELIST_H
#define AMWHITELIST_H

#include <CoreFoundation/CFURL.h>
#include "AMBase.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct __AMWhitelist;
typedef struct __AMWhitelist *AMWhitelistRef;

#define AM_GLOBAL_WHITELIST_PATH "/private/var/ammonia/core/ammonia_global.whitelist"

/// Creates and assigns an AMWhitelistRef to the out parameter. Error is returned if creation is not possible, the input was invalid, or, returns AMError.AMSuccess if all checks succeed.
AMError AMWhitelistCreateWithWhitelistAtURL(CFURLRef URL, AMWhitelistRef AM_RETURNS_RETAINED *out);

/// Returns the AMTypeID for AMWhitelist objects.
AMTypeID AMWhitelistGetTypeID(void);

/// Returns whether or not the executable is whitelisted by the file. This function explicitly ignores the intermediate path components of the provided CFURL, and checks only the last path component of the provided CFURL.
bool AMWhitelistGetExecutableIsWhitelisted(AMWhitelistRef obj, CFURLRef executable_URL);

/// Returns whether or not the full path is whitelisted by the file.
bool AMWhitelistGetFullPathIsWhitelisted(AMWhitelistRef obj, CFStringRef path);

/// Returns the count of items inside the whitelist.
CFIndex AMWhitelistGetCount(AMWhitelistRef whitelist);

/// Creates and assigns an AMWhitelistRef to the out parameter. Error is return if creation is not possible. The whitelist is read from the global location (/private/var/ammonia/core/ammonia\_global.whitelist).
AMError AMWhitelistCreateFromGlobalWhitelist(AMWhitelistRef AM_RETURNS_RETAINED *out);

#ifdef __cplusplus
}
#endif

#endif /* AMWHITELIST_H */
