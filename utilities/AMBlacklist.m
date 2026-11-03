//Created by Salty on 10/31/26.

#include <pthread.h>
#include <stdlib.h>
#include "AMBlacklist.h"
#include "_AMBase.h"
#include "AMList.h"

CFURLRef GlobalBlacklistURL(void);

struct __AMBlacklist {
    AMBase      base;
    AMListRef   list;
};

static void Destructor(AMTypeRef obj){
    struct __AMBlacklist *list = (struct __AMBlacklist *)obj;

    if (list->list)
        AMRelease(list->list);
}

static const AMClass kBlacklistClass = {
    .name = "AMBlacklist",
    .destructor = Destructor
};

static AMTypeID gBlacklistTypeID = AMTypeIDInvalid;
static pthread_once_t gInitOnce = PTHREAD_ONCE_INIT;

static void RegisterClass(void){
    gBlacklistTypeID = AMRegisterClass(&kBlacklistClass);
}

AMTypeID AMBlacklistGetTypeID(void){
    pthread_once(&gInitOnce, RegisterClass);
    return gBlacklistTypeID;
}

static AMBlacklistRef AMBlacklistCreate(void){
    struct __AMBlacklist *list = (struct __AMBlacklist *)AMCreateInstance(AMBlacklistGetTypeID(),
                                                                          sizeof(*list));
    return list;
}

CFIndex AMBlacklistGetCount(AMBlacklistRef list){
    if (list == NULL || list->list == NULL)
        return 0;
    return AMListGetCount(list->list);
}

AMError AMBlacklistCreateWithBlacklistAtURL(CFURLRef URL, AMBlacklistRef *out){
    if (URL == NULL)
        return AMErrorURLIsNULL;
    
    if (out == NULL)
        return AMErrorOutParamIsNULL;
    
    CFStringRef extension = CFURLCopyPathExtension(URL);
    
    if (extension == NULL)
        return AMErrorURLDoesNotHaveExtension;
    
    if (CFStringCompare(extension,
                        CFSTR("blacklist"),
                        kCFCompareCaseInsensitive) != kCFCompareEqualTo){
        CFRelease(extension);
        return AMErrorURLDoesNotMatchExpectedExtension;
    }
    
    CFRelease(extension);
    
    AMListRef inner_list =
        AMListCreateWithFileAtURL(URL);
    
    if (!inner_list)
        return AMErrorCouldNotParseFile;
    
    AMBlacklistRef return_list =
        AMBlacklistCreate();
    
    if (!return_list){
        AMRelease(inner_list);
        return AMErrorCouldNotAllocateBaseClass;
    }
    
    AMListRef global_list = AMListCreateWithFileAtURL(GlobalBlacklistURL());
    
    if (global_list){
        AMListAppendList(inner_list, global_list);
        AMRelease(global_list);
    }
    
    return_list->list = inner_list;
    
    *out = return_list;
    return AMSuccess;
}

bool AMBlacklistGetExecutableIsBlacklisted(AMBlacklistRef obj, CFURLRef executable_URL){
    if (obj == NULL || executable_URL == NULL || obj->list == NULL)
        return true;
    
    if (AMBlacklistGetCount(obj) == 0)
        return false;
    
    CFStringRef last_path_component = CFURLCopyLastPathComponent(executable_URL);
    
    if (!last_path_component){
        return true;
    }
    
    bool contains = AMListContainsString(obj->list, last_path_component);
    
    CFRelease(last_path_component);
    
    return contains;
}

static bool PathContainsTypicallyProblematicDirectory(CFStringRef application_full_path){
    CFArrayRef components = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,
                                                                   application_full_path,
                                                                   CFSTR("/"));
    
    if (components == NULL)
        return true;
    
    CFStringRef problematic[] = {
        CFSTR("libexec"),
        CFSTR("sbin"),
        CFSTR("DriverExtensions"),
        CFSTR("Frameworks"),
        CFSTR("PrivateFrameworks"),
    };
    
    CFIndex problematic_count = sizeof(problematic) / sizeof(problematic[0]);
    CFIndex count = CFArrayGetCount(components);
    bool found = false;
    
    for (CFIndex i = 0; i < count && !found; i++){
        CFStringRef component =
            CFArrayGetValueAtIndex(components, i);
        
        for (CFIndex j = 0; j < problematic_count; j++){
            if (CFStringCompare(component,
                                problematic[j],
                                0) == kCFCompareEqualTo){
                found = true;
                break;
            }
        }
    }
    
    CFRelease(components);
    
    return found;
}

bool AMBlacklistGetFullPathIsBlacklisted(AMBlacklistRef obj, CFStringRef path){
    if (obj == NULL || path == NULL || obj->list == NULL)
        return true;

    if (PathContainsTypicallyProblematicDirectory(path))
        return true;

    if (AMBlacklistGetCount(obj) == 0)
        return false;

    return AMListContainsString(obj->list, path);
}

bool AMBlacklistGetAllExecutablesAreBlacklisted(AMBlacklistRef obj){
    if (obj == NULL || obj->list == NULL)
        return true;
    
    return AMListContainsString(obj->list, CFSTR("*"));
}

AMError AMBlacklistCreateFromGlobalBlacklist(AMBlacklistRef AM_RETURNS_RETAINED *out){
    CFStringRef global_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                         AM_GLOBAL_BLACKLIST_PATH,
                                                         kCFStringEncodingUTF8);
    
    if (!global_cfstr)
        return AMErrorCouldNotCreateInternalProperty;
    
    CFURLRef global_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                        global_cfstr,
                                                        kCFURLPOSIXPathStyle,
                                                        false);
    
    CFRelease(global_cfstr);
    
    if (!global_url)
        return AMErrorCouldNotCreateInternalProperty;
    
    AMError error = AMBlacklistCreateWithBlacklistAtURL(global_url, out);
    
    CFRelease(global_url);
    
    return error;
}

CFURLRef GlobalBlacklistURL(void){
    CFStringRef global_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                         AM_GLOBAL_BLACKLIST_PATH,
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
