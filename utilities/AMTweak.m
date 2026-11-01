//Created by Salty on 10/29/26.

#include <pthread.h>
#include <stdlib.h>
#include "_AMBase.h"
#include "AMTweak.h"
#include "AMBlacklist.h"
#include "AMWhitelist.h"

struct __AMTweak {
    AMBase base;
    CFURLRef    tweak_library_url;
    CFStringRef tweak_name;
    AMBlacklistRef  blacklisted_apps;
    AMWhitelistRef  whitelisted_apps;
};

static void Destructor(AMTypeRef obj){
    struct __AMTweak *tweak = (struct __AMTweak *)obj;

    if (tweak->blacklisted_apps)
        AMRelease(tweak->blacklisted_apps);
    
    if (tweak->whitelisted_apps)
        AMRelease(tweak->whitelisted_apps);
    
    if (tweak->tweak_library_url)
        CFRelease(tweak->tweak_library_url);

    if (tweak->tweak_name)
        CFRelease(tweak->tweak_name);
}

static const AMClass kTweakClass = {
    .name = "AMTweak",
    .destructor = Destructor
};

static AMTypeID gTweakTypeID = AMTypeIDInvalid;
static pthread_once_t gInitOnce = PTHREAD_ONCE_INIT;

static void RegisterClass(void){
    gTweakTypeID = AMRegisterClass(&kTweakClass);
}

AMTypeID AMTweakGetTypeID(void){
    pthread_once(&gInitOnce, RegisterClass);
    return gTweakTypeID;
}

static AMTweakRef AMTweakCreate(void){
    struct __AMTweak *tweak = (struct __AMTweak *)AMCreateInstance(AMTweakGetTypeID(),
                                                                   sizeof(*tweak));
    return tweak;
}

AMTweakRef AMTweakCreateWithPath(CFStringRef path){
    if (path == NULL)
        return NULL;

    AMTweakRef ref = AMTweakCreate();

    if (ref == NULL)
        return NULL;

    ref->tweak_library_url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault,
        path,
        kCFURLPOSIXPathStyle,
        false
    );

    if (ref->tweak_library_url == NULL){
        AMRelease(ref);
        return NULL;
    }

    ref->tweak_name = CFURLCopyLastPathComponent(ref->tweak_library_url);

    if (ref->tweak_name == NULL ||
        CFStringGetLength(ref->tweak_name) == 0 ||
        CFStringCompare(ref->tweak_name, CFSTR("/"), 0) == kCFCompareEqualTo){

        AMRelease(ref);
        return NULL;
    }
    
    /* BLACKLIST */

    CFURLRef blacklist_url  = CFURLCreateCopyAppendingPathExtension(kCFAllocatorDefault,
                                                                    ref->tweak_library_url,
                                                                    CFSTR("blacklist"));
    
    if (blacklist_url){
        AMBlacklistRef blacklist = NULL;
        AMError blacklist_error  = AMBlacklistCreateWithBlacklistAtURL(blacklist_url, &blacklist);
        
        CFRelease(blacklist_url);
        
        if (blacklist_error == AMSuccess && blacklist != NULL)
            ref->blacklisted_apps = blacklist;
    }
    
    /* WHITELIST */
    
    CFURLRef whitelist_url  = CFURLCreateCopyAppendingPathExtension(kCFAllocatorDefault,
                                                                    ref->tweak_library_url,
                                                                    CFSTR("whitelist"));

    if (whitelist_url){
        AMWhitelistRef whitelist = NULL;
        AMError whitelist_error  = AMWhitelistCreateWithWhitelistAtURL(whitelist_url, &whitelist);
        
        CFRelease(whitelist_url);
        
        if (whitelist_error == AMSuccess && whitelist != NULL)
            ref->whitelisted_apps = whitelist;
    }

    return ref;
}

bool AMTweakInjectionComparator(CFStringRef path, AMWhitelistRef wl, AMBlacklistRef bl){
    bool should_inject = true;
    
    if (AMBlacklistGetAllExecutablesAreBlacklisted(bl))
        should_inject = false;
    
    if (should_inject && AMBlacklistGetFullPathIsBlacklisted(bl, path))
        should_inject = false;
    
    CFURLRef application_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                             path,
                                                             kCFURLPOSIXPathStyle,
                                                             false);
    
    if (application_url == NULL)
        return false;
    
    if (should_inject && AMBlacklistGetExecutableIsBlacklisted(bl, application_url))
        should_inject = false;
    
    if (!should_inject){
        if (AMWhitelistGetFullPathIsWhitelisted(wl, path)){
            CFRelease(application_url);
            return true;
        }

        if (AMWhitelistGetExecutableIsWhitelisted(wl, application_url))
            should_inject = true;
    }
    
    CFRelease(application_url);
    
    return should_inject;
}

bool AMTweakShouldInjectToApplication(AMTweakRef tweak,
                                      CFStringRef application_full_path){
    if (tweak == NULL || application_full_path == NULL)
        return false;

    return AMTweakInjectionComparator(application_full_path,
                                      tweak->whitelisted_apps,
                                      tweak->blacklisted_apps);
}
