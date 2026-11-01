//Created by Salty on 10/31/26.

#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "AMList.h"
#include "_AMBase.h"

struct __AMList {
    AMBase          base;
    CFURLRef        URL;
    CFArrayRef      list;
    struct timespec last_read_modified_time;
    off_t           last_read_file_size;
    ino_t           last_read_inode;
    pthread_mutex_t lock;
};

static void Destructor(AMTypeRef obj){
    struct __AMList *list = (struct __AMList *)obj;

    if (list->list)
        CFRelease(list->list);

    if (list->URL)
        CFRelease(list->URL);

    pthread_mutex_destroy(&list->lock);
}

static const AMClass kListClass = {
    .name = "AMList",
    .destructor = Destructor
};

static AMTypeID gListTypeID = AMTypeIDInvalid;
static pthread_once_t gInitOnce = PTHREAD_ONCE_INIT;

static void RegisterClass(void){
    gListTypeID = AMRegisterClass(&kListClass);
}

AMTypeID AMListGetTypeID(void){
    pthread_once(&gInitOnce, RegisterClass);
    return gListTypeID;
}

static AMListRef AMListCreate(void){
    struct __AMList *list = (struct __AMList *)AMCreateInstance(AMListGetTypeID(),
                                                                sizeof(*list));
    if (list == NULL)
        return NULL;

    pthread_mutex_init(&list->lock, NULL);

    return list;
}

#pragma mark - File parsing

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
            (CFIndex)(length - start),
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

static bool GetPathForURL(CFURLRef url, char *path, size_t path_size){
    if (url == NULL)
        return false;

    return CFURLGetFileSystemRepresentation(url,
                                            true,
                                            (UInt8 *)path,
                                            (CFIndex)path_size);
}

static bool StatURL(CFURLRef url, struct stat *out){
    char path[PATH_MAX];

    if (!GetPathForURL(url, path, sizeof(path)))
        return false;

    return stat(path, out) == 0;
}

static CFArrayRef LoadTweakConfigurationFile(CFURLRef url){
    char path[PATH_MAX];

    if (!GetPathForURL(url, path, sizeof(path)))
        return NULL;

    FILE *file = fopen(path, "r");

    if (file == NULL)
        return NULL;

    CFArrayRef array = ParseTweakConfigurationFile(file);

    fclose(file);

    return array;
}

static CFArrayRef CopyArray(AMListRef list){
    pthread_mutex_lock(&list->lock);
    CFArrayRef array = list->list ? (CFArrayRef)CFRetain(list->list) : NULL;
    pthread_mutex_unlock(&list->lock);

    return array;
}

bool AMListContainsString(AMListRef list, CFStringRef string){
    if (list == NULL || string == NULL)
        return false;

    CFArrayRef array = CopyArray(list);

    if (array == NULL)
        return false;

    bool found = CFArrayContainsValue(array,
                                      CFRangeMake(0, CFArrayGetCount(array)),
                                      string);

    CFRelease(array);

    return found;
}

CFIndex AMListGetCount(AMListRef list){
    if (list == NULL)
        return 0;

    CFArrayRef array = CopyArray(list);

    if (array == NULL)
        return 0;

    CFIndex count = CFArrayGetCount(array);

    CFRelease(array);

    return count;
}

#pragma mark - Creation

AMListRef AMListCreateWithFileAtURL(CFURLRef URL) {
    if (URL == NULL)
        return NULL;

    AMListRef list = AMListCreate();

    if (list == NULL)
        return NULL;

    struct stat info;

    if (!StatURL(URL, &info)) {
        AMRelease(list);
        return NULL;
    }

    list->list = LoadTweakConfigurationFile(URL);

    if (list->list == NULL) {
        AMRelease(list);
        return NULL;
    }

    list->URL = (CFURLRef)CFRetain(URL);
    list->last_read_modified_time = info.st_mtimespec;
    list->last_read_file_size     = info.st_size;
    list->last_read_inode         = info.st_ino;

    return list;
}

#pragma mark - Reloading

AMError AMListInvalidateIfNeeded(AMListRef list){
    if (list == NULL)
        return AMErrorObjectInputParameterIsNULL;

    if (list->URL == NULL)
        return AMErrorURLIsNULL;

    struct stat info;
    bool stat_ok = StatURL(list->URL, &info);

    AMError error = AMSuccess;

    pthread_mutex_lock(&list->lock);

    if (!stat_ok) {
        error = AMErrorCouldNotParseFile;
    } else {
        bool changed =
            info.st_mtimespec.tv_sec  != list->last_read_modified_time.tv_sec  ||
            info.st_mtimespec.tv_nsec != list->last_read_modified_time.tv_nsec ||
            info.st_size              != list->last_read_file_size             ||
            info.st_ino               != list->last_read_inode;

        if (changed) {
            CFArrayRef fresh = LoadTweakConfigurationFile(list->URL);

            if (fresh) {
                CFArrayRef old = list->list;
                list->list = fresh;

                if (old)
                    CFRelease(old);
            } else {
                error = AMErrorCouldNotParseFile;
            }

            // Record the stamp even on failure so a corrupt file is not
            // re-parsed on every call. It will be retried as soon as the
            // file changes again.
            list->last_read_modified_time = info.st_mtimespec;
            list->last_read_file_size     = info.st_size;
            list->last_read_inode         = info.st_ino;
        }
    }

    pthread_mutex_unlock(&list->lock);

    return error;
}

#pragma mark - Appending

AMError AMListAppendList(AMListRef list, AMListRef to_append){
    if (list == NULL || to_append == NULL)
        return AMErrorObjectInputParameterIsNULL;

    if (list == to_append)
        return AMSuccess;

    CFArrayRef additions = CopyArray(to_append);

    if (additions == NULL)
        return AMSuccess;

    CFIndex add_count = CFArrayGetCount(additions);

    if (add_count == 0) {
        CFRelease(additions);
        return AMSuccess;
    }

    AMError error = AMSuccess;

    pthread_mutex_lock(&list->lock);

    CFMutableArrayRef merged = list->list
        ? CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, list->list)
        : CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);

    if (merged) {
        CFArrayAppendArray(merged, additions, CFRangeMake(0, add_count));

        CFArrayRef old = list->list;
        list->list = merged;            // ownership of +1 transfers to the list

        if (old)
            CFRelease(old);
    } else {
        error = AMErrorCouldNotCreateInternalProperty;
    }

    pthread_mutex_unlock(&list->lock);

    CFRelease(additions);

    return error;
}
