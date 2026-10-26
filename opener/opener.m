//
//  opener.c
//  opener
//

#include "opener.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef void (*LoadFunction_t)(void *);
typedef void (*GumInitEmbeddedFunc_t)(void);
typedef void *(*GumInterceptorObtainFunc_t)(void);

static pthread_mutex_t opener_lock = PTHREAD_MUTEX_INITIALIZER;
static bool opener_running = false;
static bool opener_complete = false;

static void *gum_handle = NULL;
static void *gum_interceptor = NULL;
static pthread_once_t gum_init_once = PTHREAD_ONCE_INIT;
static bool gum_init_success = false;

static void initialize_gum(void);

/*
 * Returns a heap-allocated executable path.
 * The caller owns the returned memory.
 */
char *GetExePath(void)
{
    uint32_t size = 0;

    (void)_NSGetExecutablePath(NULL, &size);

    if (size == 0) {
        syslog(LOG_ERR, "GetExePath: unable to determine path size");
        return NULL;
    }

    char *buffer = malloc((size_t)size);
    if (!buffer) {
        syslog(LOG_ERR, "GetExePath: allocation failed");
        return NULL;
    }

    if (_NSGetExecutablePath(buffer, &size) != 0) {
        syslog(LOG_ERR, "GetExePath: path retrieval failed");
        free(buffer);
        return NULL;
    }

    char *canonical = realpath(buffer, NULL);

    if (canonical) {
        free(buffer);
        return canonical;
    }

    /*
     * Keep the original path if canonicalization fails.
     */
    return buffer;
}

static bool has_suffix(const char *string, const char *suffix)
{
    if (!string || !suffix) {
        return false;
    }

    size_t string_len = strlen(string);
    size_t suffix_len = strlen(suffix);

    return string_len >= suffix_len &&
           memcmp(string + string_len - suffix_len,
                  suffix, suffix_len) == 0;
}

static void trim_line(char *line)
{
    if (!line) {
        return;
    }

    line[strcspn(line, "\r\n")] = '\0';

    char *start = line;

    while (*start == ' ' || *start == '\t') {
        ++start;
    }

    if (start != line) {
        memmove(line, start, strlen(start) + 1);
    }

    size_t len = strlen(line);

    while (len > 0 &&
           (line[len - 1] == ' ' || line[len - 1] == '\t')) {
        line[--len] = '\0';
    }
}

/*
 * A rule matches either the complete executable path or its basename.
 * Blank lines and lines beginning with '#' are ignored.
 *
 * getline() avoids matching truncated, overlong rule lines.
 */
static bool file_matches_process(
    const char *rule_path,
    const char *executable_path)
{
    if (!rule_path || !executable_path) {
        return false;
    }

    FILE *file = fopen(rule_path, "r");

    if (!file) {
        syslog(LOG_ERR, "Cannot open rule file %s: %s",
               rule_path, strerror(errno));
        return false;
    }

    const char *basename = strrchr(executable_path, '/');
    basename = basename ? basename + 1 : executable_path;

    char *line = NULL;
    size_t capacity = 0;
    bool matched = false;

    while (getline(&line, &capacity, file) != -1) {
        trim_line(line);

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (strcmp(line, executable_path) == 0 ||
            strcmp(line, basename) == 0) {
            matched = true;
            break;
        }
    }

    if (ferror(file)) {
        syslog(LOG_ERR, "Error reading rule file %s", rule_path);
        matched = false;
    }

    free(line);
    fclose(file);

    return matched;
}

/*
 * Returns:
 *
 *   1: load the tweak
 *   0: skip the tweak
 *  -1: rule configuration error; skip the tweak
 *
 * Policy:
 *   1. An existing whitelist takes precedence.
 *   2. Otherwise, an existing blacklist excludes matching processes.
 *   3. If neither exists, skip the tweak.
 */
static int should_load_tweak(
    const char *directory,
    const char *filename,
    const char *executable_path)
{
    char whitelist[PATH_MAX];
    char blacklist[PATH_MAX];

    int wn = snprintf(
        whitelist, sizeof(whitelist),
        "%s/tweaks/%s.whitelist", directory, filename);

    int bn = snprintf(
        blacklist, sizeof(blacklist),
        "%s/tweaks/%s.blacklist", directory, filename);

    if (wn < 0 || (size_t)wn >= sizeof(whitelist) ||
        bn < 0 || (size_t)bn >= sizeof(blacklist)) {
        syslog(LOG_ERR, "Rule path too long for tweak %s", filename);
        return -1;
    }

    struct stat st;

    if (stat(whitelist, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            syslog(LOG_ERR, "Whitelist is not a regular file: %s",
                   whitelist);
            return -1;
        }

        bool match = file_matches_process(
            whitelist, executable_path);

        if (!match) {
            syslog(LOG_INFO, "Skipping %s: not whitelisted for %s",
                   filename, executable_path);
        }

        return match ? 1 : 0;
    }

    if (errno != ENOENT) {
        syslog(LOG_ERR, "Cannot inspect whitelist %s: %s",
               whitelist, strerror(errno));
        return -1;
    }

    if (stat(blacklist, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            syslog(LOG_ERR, "Blacklist is not a regular file: %s",
                   blacklist);
            return -1;
        }

        bool match = file_matches_process(
            blacklist, executable_path);

        if (match) {
            syslog(LOG_INFO, "Skipping %s: blacklisted for %s",
                   filename, executable_path);
        }

        return match ? 0 : 1;
    }

    if (errno != ENOENT) {
        syslog(LOG_ERR, "Cannot inspect blacklist %s: %s",
               blacklist, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "Skipping %s: no whitelist or blacklist",
           filename);

    return 0;
}

/*
 * Load a tweak and resolve its entry point.
 *
 * Handles are intentionally retained. A tweak may have constructors,
 * registered callbacks, or persistent state that makes unloading unsafe.
 */
static void load_tweak(
    const char *path,
    const char *filename,
    void *interceptor)
{
    dlerror();

    void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);

    if (!handle) {
        const char *error = dlerror();

        syslog(LOG_ERR, "Failed to load tweak %s: %s",
               path, error ? error : "unknown error");
        return;
    }

    dlerror();

    LoadFunction_t load =
        (LoadFunction_t)dlsym(handle, "LoadFunction");

    const char *error = dlerror();

    if (error || !load) {
        syslog(LOG_ERR, "Tweak %s has no usable LoadFunction: %s",
               filename, error ? error : "symbol not found");
        return;
    }

    syslog(LOG_INFO, "Initializing tweak %s", filename);

    /*
     * Native crashes and Objective-C exceptions are not caught here.
     */
    load(interceptor);
}

/*
 * Scan and initialize eligible tweaks.
 *
 * The caller must provide a valid Frida interceptor.
 */
void Open(void *interceptor)
{
    if (!interceptor) {
        syslog(LOG_ERR, "Open: invalid Frida interceptor");
        return;
    }

    /*
     * Prevent concurrent and repeated scans.
     * Release the mutex before invoking third-party tweak code.
     */
    pthread_mutex_lock(&opener_lock);

    if (opener_running || opener_complete) {
        pthread_mutex_unlock(&opener_lock);
        return;
    }

    opener_running = true;
    pthread_mutex_unlock(&opener_lock);

    char *executable_path = GetExePath();

    if (!executable_path) {
        syslog(LOG_ERR, "Open: could not determine executable path");
        goto done;
    }

    char tweaks_directory[PATH_MAX];

    int n = snprintf(
        tweaks_directory, sizeof(tweaks_directory),
        "%stweaks/", SupportFolderP);

    if (n < 0 || (size_t)n >= sizeof(tweaks_directory)) {
        syslog(LOG_ERR, "Open: tweaks directory path is too long");
        free(executable_path);
        goto done;
    }

    DIR *directory = opendir(tweaks_directory);

    if (!directory) {
        syslog(LOG_ERR, "Cannot open tweaks directory %s: %s",
               tweaks_directory, strerror(errno));
        free(executable_path);
        goto done;
    }

    struct dirent *entry;

    while ((entry = readdir(directory)) != NULL) {
        const char *filename = entry->d_name;

        if (filename[0] == '.') {
            continue;
        }

        if (!has_suffix(filename, ".dylib")) {
            continue;
        }

        char path[PATH_MAX];

        n = snprintf(path, sizeof(path), "%s%s",
                     tweaks_directory, filename);

        if (n < 0 || (size_t)n >= sizeof(path)) {
            syslog(LOG_ERR, "Skipping oversized tweak path: %s",
                   filename);
            continue;
        }

        struct stat st;

        if (stat(path, &st) != 0) {
            syslog(LOG_WARNING, "Cannot inspect tweak %s: %s",
                   path, strerror(errno));
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            syslog(LOG_WARNING, "Skipping non-regular tweak: %s", path);
            continue;
        }

        int decision = should_load_tweak(
            SupportFolderP, filename, executable_path);

        if (decision != 1) {
            continue;
        }

        load_tweak(path, filename, interceptor);
    }

    if (closedir(directory) != 0) {
        syslog(LOG_WARNING, "Error closing tweaks directory: %s",
               strerror(errno));
    }

    free(executable_path);

done:
    pthread_mutex_lock(&opener_lock);
    opener_running = false;
    opener_complete = true;
    pthread_mutex_unlock(&opener_lock);
}

/*
 * Initialize Frida Gum exactly once.
 *
 * Keep the dlopen handle alive for as long as its API is in use.
 */
static void initialize_gum(void)
{
    static const char *gum_path =
        "/private/var/ammonia/core/fridagum.dylib";

    void *handle = dlopen(gum_path, RTLD_NOW | RTLD_GLOBAL);

    if (!handle) {
        const char *error = dlerror();

        syslog(LOG_ERR, "Cannot load Frida Gum: %s",
               error ? error : "unknown error");
        return;
    }

    dlerror();

    GumInitEmbeddedFunc_t init =
        (GumInitEmbeddedFunc_t)dlsym(handle, "gum_init_embedded");

    const char *init_error = dlerror();

    dlerror();

    GumInterceptorObtainFunc_t obtain =
        (GumInterceptorObtainFunc_t)dlsym(
            handle, "gum_interceptor_obtain");

    const char *obtain_error = dlerror();

    if (init_error || obtain_error || !init || !obtain) {
        syslog(LOG_ERR,
               "Frida Gum API unavailable (init: %s, obtain: %s)",
               init_error ? init_error : "ok",
               obtain_error ? obtain_error : "ok");

        /*
         * Retain the handle even on partial initialization.
         */
        gum_handle = handle;
        return;
    }

    init();

    void *interceptor = obtain();

    if (!interceptor) {
        syslog(LOG_ERR, "Frida Gum returned a null interceptor");
        gum_handle = handle;
        return;
    }

    gum_handle = handle;
    gum_interceptor = interceptor;
    gum_init_success = true;
}

void __attribute__((constructor)) ctor_main(void)
{
    pthread_once(&gum_init_once, initialize_gum);

    if (!gum_init_success || !gum_handle || !gum_interceptor) {
        syslog(LOG_ERR, "Frida Gum initialization failed");
        return;
    }

    Open(gum_interceptor);
}
