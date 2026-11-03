//Created by Salty on 10/31/26.

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include "AMWhitelist.h"
#include "_AMBase.h"
#include "AMList.h"

CFURLRef GlobalWhitelistURL(void);

struct __AMWhitelist {
    AMBase      base;
    AMListRef   list;
};

static void Destructor(AMTypeRef obj){
    struct __AMWhitelist *list = (struct __AMWhitelist *)obj;

    if (list->list)
        AMRelease(list->list);
}

static const AMClass kWhitelistClass = {
    .name = "AMWhitelist",
    .destructor = Destructor
};

static AMTypeID gWhitelistTypeID = AMTypeIDInvalid;
static pthread_once_t gInitOnce = PTHREAD_ONCE_INIT;

static void RegisterClass(void){
    gWhitelistTypeID = AMRegisterClass(&kWhitelistClass);
}

AMTypeID AMWhitelistGetTypeID(void){
    pthread_once(&gInitOnce, RegisterClass);
    return gWhitelistTypeID;
}

static AMWhitelistRef AMWhitelistCreate(void){
    struct __AMWhitelist *list = (struct __AMWhitelist *)AMCreateInstance(AMWhitelistGetTypeID(),
                                                                          sizeof(*list));
    return list;
}

CFIndex AMWhitelistGetCount(AMWhitelistRef list){
    if (list == NULL || list->list == NULL)
        return 0;
    
    return (AMListGetCount(list->list));
}

AMError AMWhitelistCreateWithWhitelistAtURL(CFURLRef URL, AMWhitelistRef *out){
    if (URL == NULL)
        return AMErrorURLIsNULL;
    
    if (out == NULL)
        return AMErrorOutParamIsNULL;
    
    CFStringRef extension = CFURLCopyPathExtension(URL);
    
    if (extension == NULL)
        return AMErrorURLDoesNotHaveExtension;
    
    if (CFStringCompare(extension,
                        CFSTR("whitelist"),
                        kCFCompareCaseInsensitive) != kCFCompareEqualTo){
        CFRelease(extension);
        return AMErrorURLDoesNotMatchExpectedExtension;
    }
    
    CFRelease(extension);
    
    AMListRef inner_list =
        AMListCreateWithFileAtURL(URL);
    
    if (!inner_list)
        return AMErrorCouldNotParseFile;
    
    AMWhitelistRef return_list =
        AMWhitelistCreate();
    
    if (!return_list){
        AMRelease(inner_list);
        return AMErrorCouldNotAllocateBaseClass;
    }
    
    AMListRef global_list = AMListCreateWithFileAtURL(GlobalWhitelistURL());
    
    if (global_list){
        AMListAppendList(inner_list, global_list);
        AMRelease(global_list);
    }
    
    return_list->list = inner_list;
    
    *out = return_list;
    return AMSuccess;
}

bool AMWhitelistGetExecutableIsWhitelisted(AMWhitelistRef obj, CFURLRef executable_URL){
    if (obj == NULL || executable_URL == NULL || obj->list == NULL)
        return false;
    
    if (AMWhitelistGetCount(obj) == 0)
        return false;
    
    CFStringRef last_path_component = CFURLCopyLastPathComponent(executable_URL);
    
    if (!last_path_component){
        return false;
    }
    
    bool contains = AMListContainsString(obj->list, last_path_component);
    
    CFRelease(last_path_component);
    
    return contains;
}

bool AMWhitelistGetFullPathIsWhitelisted(AMWhitelistRef obj, CFStringRef path){
    if (obj == NULL || path == NULL || obj->list == NULL)
        return false;
    
    if (AMWhitelistGetCount(obj) == 0)
        return false;
    
    return AMListContainsString(obj->list, path);
}

CFURLRef GlobalWhitelistURL(void){
    CFStringRef global_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                         AM_GLOBAL_WHITELIST_PATH,
                                                         kCFStringEncodingUTF8);
    
    if (!global_cfstr)
        return NULL;
    
    CFURLRef global_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                        global_cfstr,
                                                        kCFURLPOSIXPathStyle,
                                                        false);
    
    CFRelease(global_cfstr);
    
    return global_url;
}

AMError AMWhitelistCreateFromGlobalWhitelist(AMWhitelistRef AM_RETURNS_RETAINED *out){
    CFURLRef global_url = GlobalWhitelistURL();
    
    if (!global_url)
        return AMErrorCouldNotCreateInternalProperty;
    
    AMError error = AMWhitelistCreateWithWhitelistAtURL(global_url, out);
    
    CFRelease(global_url);
    
    return error;
}


