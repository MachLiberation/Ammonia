//Created by Salty on 10/29/26.

#include "AMTweak.h"

struct __AMTweak {
    CFURLRef    tweak_library_url;
    CFStringRef tweak_name;
    CFArrayRef  blacklisted_apps;
    CFArrayRef  whitelisted_apps;
};

static AMTweakRef AMTweakCreate(void){
    struct __AMTweak *ref = calloc(1, sizeof(*ref));

    if (ref == NULL)
        return NULL;
    
    return ref;
}

static CFArrayRef ParseTweakConfigurationFile(FILE *file){
    if (file == NULL)
        return NULL;

    CFMutableArrayRef array = CFArrayCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeArrayCallBacks
    );

    if (array == NULL)
        return NULL;

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;

    while ((length = getline(&line, &capacity, file)) != -1){

        // Trim trailing whitespace.
        while (length > 0 &&
               isspace((unsigned char)line[length - 1])){
            line[--length] = '\0';
        }

        // Trim leading whitespace.
        size_t start = 0;

        while (start < (size_t)length &&
               isspace((unsigned char)line[start])){
            start++;
        }

        // Ignore blank lines.
        if (start == (size_t)length)
            continue;

        // Ignore comments.
        if (line[start] == '#' ||
            (line[start] == '/' && line[start + 1] == '/')){
            continue;
        }

        // Create a CFString from the line.
        CFStringRef entry = CFStringCreateWithBytes(
            kCFAllocatorDefault,
            (const UInt8 *)(line + start),
            length - start,
            kCFStringEncodingUTF8,
            false
        );

        if (entry == NULL){
            free(line);
            CFRelease(array);
            return NULL;
        }

        CFArrayAppendValue(array, entry);
        CFRelease(entry);
    }

    free(line);

    if (ferror(file)){
        CFRelease(array);
        return NULL;
    }

    return array;
}

static CFArrayRef LoadTweakConfigurationFile(CFURLRef url){
    if (url == NULL)
        return NULL;

    char filesystem_path[PATH_MAX];

    if (!CFURLGetFileSystemRepresentation(
            url,
            true,
            (UInt8 *)filesystem_path,
            sizeof(filesystem_path)))
        return NULL;

    FILE *file = fopen(filesystem_path, "r");

    if (file == NULL)
        return NULL;

    CFArrayRef array = ParseTweakConfigurationFile(file);

    fclose(file);

    return array;
}

static CFArrayRef LoadTweakConfigurationFileWithExtension(CFURLRef library_url,
                                                          CFStringRef extension){
    CFURLRef config_url = CFURLCreateCopyAppendingPathExtension(
        kCFAllocatorDefault,
        library_url,
        extension
    );

    if (config_url == NULL)
        return NULL;

    CFArrayRef array = LoadTweakConfigurationFile(config_url);

    CFRelease(config_url);

    return array;
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
        AMTweakRelease(ref);
        return NULL;
    }

    ref->tweak_name = CFURLCopyLastPathComponent(ref->tweak_library_url);

    if (ref->tweak_name == NULL ||
        CFStringGetLength(ref->tweak_name) == 0 ||
        CFStringCompare(ref->tweak_name, CFSTR("/"), 0) == kCFCompareEqualTo){

        AMTweakRelease(ref);
        return NULL;
    }

    ref->blacklisted_apps = LoadTweakConfigurationFileWithExtension(ref->tweak_library_url, CFSTR("blacklist"));

    ref->whitelisted_apps = LoadTweakConfigurationFileWithExtension(ref->tweak_library_url, CFSTR("whitelist"));

    return ref;
}

static bool PathContainsTypicallyProblematicDirectory(CFStringRef application_full_path){
    CFArrayRef components = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,
                                                                   application_full_path,
                                                                   CFSTR("/"));
    
    if (components == NULL)
        return false;
    
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

static bool ArrayContainsString(CFArrayRef array, CFStringRef string){
    if (array == NULL || string == NULL)
        return false;
    
    return CFArrayContainsValue(array,
                                CFRangeMake(0, CFArrayGetCount(array)),
                                string);
}

bool AMTweakShouldInjectToApplication(AMTweakRef tweak,
                                      CFStringRef application_full_path){
    bool should_inject = true;
    
    if (tweak == NULL
        || application_full_path == NULL)
        return false;
    
    CFURLRef application_url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault,
        application_full_path,
        kCFURLPOSIXPathStyle,
        false
    );
    
    if (application_url == NULL)
        return false;
    
    CFStringRef application_name =
        CFURLCopyLastPathComponent(application_url);
    
    CFRelease(application_url);
    
    if (application_name == NULL)
        return false;
    
    // A missing or empty list file is treated as "no list".
    bool has_blacklist =
        tweak->blacklisted_apps != NULL && CFArrayGetCount(tweak->blacklisted_apps) > 0;
    bool has_whitelist =
        tweak->whitelisted_apps != NULL && CFArrayGetCount(tweak->whitelisted_apps) > 0;
    
    // Problematic directory: no, unless a whitelist entry overrides below.
    should_inject =
        !PathContainsTypicallyProblematicDirectory(application_full_path);
    
    // Blacklist: "*" blocks everything, otherwise block exact name matches.
    if (should_inject && has_blacklist){
        if (ArrayContainsString(tweak->blacklisted_apps, CFSTR("*")) ||
            ArrayContainsString(tweak->blacklisted_apps, application_name)){
            should_inject = false;
        }
    }
    
    // No blacklist means nothing is injected by default: either only a whitelist
    // was provided (only whitelisted apps get in), or no lists at all (nothing does).
    if (should_inject && !has_blacklist){
        should_inject = false;
    }
    
    // Whitelist comes last so it overrides any of the blocks above (including problematic directory check, but that is why a whitelist is explicit).
    if (!should_inject && has_whitelist){
        if (ArrayContainsString(tweak->whitelisted_apps, application_name))
            should_inject = true;
    }
    
    CFRelease(application_name);
    
    return should_inject;
}

void AMTweakRelease(AMTweakRef tweak){
    if (tweak == NULL)
        return;
    
    if (tweak->blacklisted_apps != NULL)
        CFRelease(tweak->blacklisted_apps);
    
    if (tweak->whitelisted_apps != NULL)
        CFRelease(tweak->whitelisted_apps);
    
    if (tweak->tweak_name != NULL)
        CFRelease(tweak->tweak_name);
    
    if (tweak->tweak_library_url != NULL)
        CFRelease(tweak->tweak_library_url);
    
    free(tweak);
}
