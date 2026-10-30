//Created by Salty on 10/29/26.

#include "AMTweak.h"

struct __AMTweak {
    CFStringRef tweak_library_path;
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

static CFArrayRef LoadTweakConfigurationFile(CFStringRef path){

    char filesystem_path[PATH_MAX];

    if (!CFStringGetFileSystemRepresentation(
            path,
            filesystem_path,
            sizeof(filesystem_path)))
        return NULL;

    FILE *file = fopen(filesystem_path, "r");

    if (file == NULL)
        return NULL;

    CFArrayRef array = ParseTweakConfigurationFile(file);

    fclose(file);

    return array;
}

AMTweakRef AMTweakCreateWithPath(CFStringRef path){
    if (path == NULL)
        return NULL;

    AMTweakRef ref = AMTweakCreate();

    if (ref == NULL)
        return NULL;

    ref->tweak_library_path = CFStringCreateCopy(
        kCFAllocatorDefault,
        path
    );

    if (ref->tweak_library_path == NULL){
        AMTweakRelease(ref);
        return NULL;
    }

    CFRange slash = CFStringFind(
        path,
        CFSTR("/"),
        kCFCompareBackwards
    );

    CFIndex path_length = CFStringGetLength(path);

    if (slash.location == kCFNotFound ||
        slash.location == path_length - 1){

        AMTweakRelease(ref);
        return NULL;
    }

    CFRange component_range = CFRangeMake(
        slash.location + 1,
        path_length - slash.location - 1
    );

    ref->tweak_name = CFStringCreateWithSubstring(
        kCFAllocatorDefault,
        path,
        component_range
    );

    if (ref->tweak_name == NULL){
        AMTweakRelease(ref);
        return NULL;
    }

    CFMutableStringRef blacklist_mutable =
        CFStringCreateMutableCopy(
                                  kCFAllocatorDefault,
                                  0,
                                  ref->tweak_library_path
                                  );

    CFMutableStringRef whitelist_mutable =
        CFStringCreateMutableCopy(
                                  kCFAllocatorDefault,
                                  0,
                                  ref->tweak_library_path
                                  );

    if (blacklist_mutable == NULL ||
        whitelist_mutable == NULL){

        if (blacklist_mutable != NULL)
            CFRelease(blacklist_mutable);

        if (whitelist_mutable != NULL)
            CFRelease(whitelist_mutable);

        AMTweakRelease(ref);
        return NULL;
    }

    CFStringAppend(blacklist_mutable, CFSTR(".blacklist"));
    CFStringAppend(whitelist_mutable, CFSTR(".whitelist"));

    ref->blacklisted_apps = LoadTweakConfigurationFile(
        blacklist_mutable
    );

    ref->whitelisted_apps = LoadTweakConfigurationFile(
        whitelist_mutable
    );

    CFRelease(blacklist_mutable);
    CFRelease(whitelist_mutable);

    return ref;
}

bool AMTweakShouldInjectToApplication(AMTweakRef tweak,
                                      CFStringRef application){
    
    
    return false;
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
    
    if (tweak->tweak_library_path != NULL)
        CFRelease(tweak->tweak_library_path);
    
    free(tweak);
}
