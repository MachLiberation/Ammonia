//Created by Salty on 11/14/26.

#ifndef AMGLOBALSPROCESSOR_H
#define AMGLOBALSPROCESSOR_H

#include "AMWhitelist.h"
#include "AMBlacklist.h"

#ifdef __cplusplus
extern "C" {
#endif

/// When the global\_whitelist parameter is not NULL, checks if WindowServer is a line item in the whitelist. If the input is NULL or it does not contain WindowServer, this function returns false.
bool AMGlobalsGetWindowServerInjectionIsAllowed(AMWhitelistRef global_whitelist);

/// When the global\_whitelist parameter is not NULL, checks if the process at path is whitelisted, else returns false.
bool AMGlobalsGetGloballyAllowedProcess(AMWhitelistRef global_whitelist, const char *path);

/// When the global\_blacklist parameter is not NULL, checks if the process at path is blacklisted, else returns false. Note, this is the inverse outcome of the tweak-level blacklist check when the list is NULL. This is because a global blacklist is not required to be used.
bool AMGlobalsGetGloballyBlacklistedProcess(AMBlacklistRef global_blacklist, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* AMGLOBALSPROCESSOR_H */
