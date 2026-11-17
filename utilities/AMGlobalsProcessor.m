//Created by Salty on 11/14/26.

#include "AMGlobalsProcessor.h"
#include <dispatch/dispatch.h>

static const CFStringRef WS_CF_STR =
    CFSTR("/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer");

bool AMGlobalsGetWindowServerInjectionIsAllowed(AMWhitelistRef global_whitelist){
    if (global_whitelist == NULL)
        return false;
    
    if (AMWhitelistGetCount(global_whitelist) == 0)
        return false;
    
    CFURLRef WS_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                    WS_CF_STR,
                                                    kCFURLPOSIXPathStyle,
                                                    false);
    
    if (!WS_URL)
        return false;
    
    bool WS_INJ = false;
    
    WS_INJ = AMWhitelistGetFullPathIsWhitelisted(global_whitelist,
                                                 WS_CF_STR);
    
    if (!WS_INJ){
        WS_INJ = AMWhitelistGetExecutableIsWhitelisted(global_whitelist,
                                                       WS_URL);
    }
    
    CFRelease(WS_URL);
    return WS_INJ;
}

bool AMGlobalsGetGloballyAllowedProcess(AMWhitelistRef global_whitelist, const char *path){
    if (global_whitelist == NULL || path == NULL)
        return false;
    
    if (AMWhitelistGetCount(global_whitelist) == 0)
        return false;
    
    CFStringRef path_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                       path,
                                                       kCFStringEncodingUTF8);
    
    if (!path_cfstr)
        return false;
    
    CFURLRef path_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                      path_cfstr,
                                                      kCFURLPOSIXPathStyle,
                                                      false);
    
    if (!path_URL){
        CFRelease(path_cfstr);
        return false;
    }
    
    bool allowed = false;
    
    allowed = AMWhitelistGetFullPathIsWhitelisted(global_whitelist,
                                                  path_cfstr);
    
    if (!allowed){
        allowed = AMWhitelistGetExecutableIsWhitelisted(global_whitelist,
                                                        path_URL);
    }
    
    CFRelease(path_cfstr);
    CFRelease(path_URL);
    return allowed;
}

bool AMGlobalsGetGloballyBlacklistedProcess(AMBlacklistRef global_blacklist, const char *path){
    if (global_blacklist == NULL || path == NULL)
        return false;
    
    if (AMBlacklistGetCount(global_blacklist) == 0)
        return false;
    
    CFStringRef path_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                       path,
                                                       kCFStringEncodingUTF8);
    
    if (!path_cfstr)
        return false;
    
    CFURLRef path_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                      path_cfstr,
                                                      kCFURLPOSIXPathStyle,
                                                      false);
    
    if (!path_URL){
        CFRelease(path_cfstr);
        return false;
    }
    
    bool disallowed = false;
    
    disallowed = AMBlacklistGetAllExecutablesAreBlacklisted(global_blacklist);
    
    if (!disallowed){
        disallowed = AMBlacklistGetFullPathIsBlacklisted(global_blacklist,
                                                         path_cfstr);
        
        if (!disallowed){
            disallowed = AMBlacklistGetExecutableIsBlacklisted(global_blacklist,
                                                               path_URL);
        }
    }
    
    CFRelease(path_cfstr);
    CFRelease(path_URL);
    return disallowed;
}

bool AMGlobalsGetPRIOBypassStatusForProcess(AMWhitelistRef global_whitelist, const char *path){
    if (global_whitelist == NULL || path == NULL)
        return false;
    
    if (AMWhitelistGetCount(global_whitelist) == 0)
        return false;
    
    CFStringRef path_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                       path,
                                                       kCFStringEncodingUTF8);
    
    if (!path_cfstr)
        return false;
    
    CFURLRef path_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                      path_cfstr,
                                                      kCFURLPOSIXPathStyle,
                                                      false);
    
    if (!path_URL){
        CFRelease(path_cfstr);
        return false;
    }
    
    CFStringRef last_comp = CFURLCopyLastPathComponent(path_URL);
    
    if (!last_comp){
        CFRelease(path_cfstr);
        CFRelease(path_URL);
        return false;
    }
    
    CFMutableStringRef mut_str = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, CFSTR("BypassPrio="));
    
    if (!mut_str){
        CFRelease(path_cfstr);
        CFRelease(path_URL);
        CFRelease(last_comp);
        return false;
    }
    
    CFStringAppend(mut_str, last_comp);
    
    bool bypassed = false;
    
    bypassed = AMWhitelistGetFileContainsLine(global_whitelist, mut_str);
    
    CFRelease(path_cfstr);
    CFRelease(path_URL);
    CFRelease(last_comp);
    return bypassed;
}
