//
//  libinfect.c
//  libinfect
//
//  Created by bedtime on 11/19/23.
//

#include "ammonia.h"
#include "envbuf.h"
#include "frida-gum.h"

#include <MacTypes.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <AMWhitelist.h>
#include <AMBlacklist.h>
#include <AMTweak.h>

#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#define PRIO_DARWIN_ROLE_UI_FOCAL     0x1
#define PRIO_DARWIN_ROLE_UI           0x2
#define PRIO_DARWIN_ROLE_UI_NON_FOCAL 0x4

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>

Boolean killall(const char *executablePathToKill, bool softly) {
    if (!executablePathToKill)
        return false;

    static int maxArgumentSize = 0;
    if (maxArgumentSize == 0) {
        int argmaxMib[2] = { CTL_KERN, KERN_ARGMAX };
        size_t size = sizeof(maxArgumentSize);
        if (sysctl(argmaxMib, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
            perror("sysctl argument size");
            maxArgumentSize = 4096;  // Default
        }
    }

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t length = 0;

    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
        return false;

    // Pad: processes can spawn between the two sysctl calls
    length += length / 8 + sizeof(struct kinfo_proc) * 16;

    struct kinfo_proc *info = malloc(length);
    if (!info)
        return false;

    if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
        free(info);
        return false;
    }

    // One buffer, reused for every process (+1 so we can always NUL-terminate)
    char *buffer = malloc((size_t)maxArgumentSize + 1);
    if (!buffer) {
        free(info);
        return false;
    }

    bool signaled = false;
    int count = (int)(length / sizeof(struct kinfo_proc));
    int signalToSend = softly ? SIGTERM : SIGKILL;
    pid_t myPid = getpid();

    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid <= 0 || pid == myPid)
            continue;

        int procMib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
        size_t size = (size_t)maxArgumentSize;

        if (sysctl(procMib, 3, buffer, &size, NULL, 0) != 0)
            continue;
        if (size <= sizeof(int))
            continue;

        buffer[size] = '\0';  // guarantee termination

        // Layout: [int argc][exec_path\0][padding\0...][argv...]
        const char *executablePath = buffer + sizeof(int);
        if (strcmp(executablePath, executablePathToKill) == 0) {
            if (kill(pid, signalToSend) == 0)
                signaled = true;
        }
    }

    free(buffer);
    free(info);
    return signaled;
}

#define WindowServerP "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer"

Boolean WindowServerSetForLoadingAfterBoot = false;
Boolean ApplyWindowServerFix(void) {
    if (!WindowServerSetForLoadingAfterBoot) {
        Boolean killed = killall(
            WindowServerP,
            false);
        WindowServerSetForLoadingAfterBoot = killed;
        return killed;
    }
    return true;
}

static int (*SpawnOld)(
    pid_t *, const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const  [], char *const []
);

static int (*SpawnPOld)(
    pid_t *, const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const [], char *const []
);
  
static bool IsGUIRole(uint64_t role)
{
    return role == PRIO_DARWIN_ROLE_UI_FOCAL ||
           role == PRIO_DARWIN_ROLE_UI ||
           role == 3 ||
           role == PRIO_DARWIN_ROLE_UI_NON_FOCAL;
}

static bool IsAllowedProcess(uint64_t PRIO_DARWIN_ROLE_T, const char *path, AMWhitelistRef whitelist){
    if (IsGUIRole(PRIO_DARWIN_ROLE_T))
        return true;
    
    if (whitelist && AMWhitelistGetCount(whitelist) > 0 && path){
        bool wl_determination = false;
        CFStringRef path_cfstr = CFStringCreateWithCString(kCFAllocatorDefault,
                                                           path,
                                                           kCFStringEncodingUTF8);
        
        wl_determination = AMWhitelistGetFullPathIsWhitelisted(whitelist,
                                                               path_cfstr);
        
        if (path_cfstr){
            CFURLRef path_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                              path_cfstr,
                                                              kCFURLPOSIXPathStyle,
                                                              false);
            
            CFRelease(path_cfstr);
            
            wl_determination  = AMWhitelistGetExecutableIsWhitelisted(whitelist,
                                                                      path_URL);
            
            if (path_URL)
                CFRelease(path_URL);
        }
        
        return wl_determination;
    }
    
    return false;
}

int posix_spawnattr_get_darwin_role_np(const posix_spawnattr_t * __restrict, uint64_t * __restrict) __API_AVAILABLE(macos(10.11), ios(9.0));

static int SpawnWrapper(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attr,
    char *const argv[],
    char *const envp[],
    bool spawnp)
{
    AMWhitelistRef global_whitelist = NULL;
    AMError wl_creation_result = AMWhitelistCreateFromGlobalWhitelist(&global_whitelist);
    
    if (getpid() == 1 && WindowServerSetForLoadingAfterBoot == false){
        if (global_whitelist
            && wl_creation_result == AMSuccess){
            CFStringRef windowserver_cfstr_path = CFStringCreateWithCString(kCFAllocatorDefault,
                                                                            WindowServerP,
                                                                            kCFStringEncodingUTF8);
            
            if (windowserver_cfstr_path != NULL){
                CFURLRef windowserver_URL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                                          windowserver_cfstr_path,
                                                                          kCFURLPOSIXPathStyle,
                                                                          false);
                
                CFRelease(windowserver_cfstr_path);
                
                if (windowserver_URL != NULL){
                    if (AMWhitelistGetExecutableIsWhitelisted(global_whitelist,
                                                              windowserver_URL)){
                        ApplyWindowServerFix();
                    }
                    
                    CFRelease(windowserver_URL);
                }
            }
        }
    }
    
    char **env = envbuf_mutcopy((const char **)envp);

    if (!env) {
        if (global_whitelist)
            AMRelease(global_whitelist);
        
        return spawnp
            ? SpawnPOld(pid, path, actions, attr, argv, envp)
            : SpawnOld(pid, path, actions, attr, argv, envp);
    }

    uint64_t role = 0;
    if (attr) {
        posix_spawnattr_get_darwin_role_np(attr, &role);
    }

    /* BEGIN - INSERT LIBOPENER & LIBLIBINFECT */

    if (path && strcmp(path, "/usr/libexec/xpcproxy") == 0){
        envbuf_setenv(&env, "DYLD_INSERT_LIBRARIES",
                      SupportFolderP "liblibinfect.dylib");
    } else if (path
               && (strstr(path, "Driver") == NULL)
               && IsAllowedProcess(role, path, global_whitelist)){
GraphicalProcess: ;
        
        const char *library = SupportFolderP "libopener.dylib";
        int index = envbuf_find((const char **)env,
                                "DYLD_INSERT_LIBRARIES");

        if (index >= 0){
            const char *existing = env[index] + strlen("DYLD_INSERT_LIBRARIES=");

            char *combined = NULL;

            if (asprintf(&combined, "%s:%s", existing, library) >= 0) {
                envbuf_setenv(&env, "DYLD_INSERT_LIBRARIES", combined);
                free(combined);
            }
        } else {
            envbuf_setenv(&env, "DYLD_INSERT_LIBRARIES", library);
        }
    }
    
    /* END - INSERT LIBOPENER & LIBLIBINFECT */

    int result = spawnp
        ? SpawnPOld(pid, path, actions, attr, argv, env)
        : SpawnOld(pid, path, actions, attr, argv, env);

    envbuf_free(env);
    
    if (global_whitelist)
        AMRelease(global_whitelist);
    
    return result;
}

static int SpawnNew(
    pid_t *restrict pid,
    const char *restrict path,
    const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *restrict attr,
    char *const argv[],
    char *const envp[])
{
    return SpawnWrapper(pid,
                        path,
                        actions,
                        attr,
                        (char *const *)argv,
                        (char *const *)envp,
                        false);
}

static int SpawnPNew(
    pid_t *restrict pid,
    const char *restrict path,
    const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *restrict attr,
    char *const argv[],
    char *const envp[])
{
    return SpawnWrapper(pid,
                        path,
                        actions,
                        attr,
                        (char *const *)argv,
                        (char *const *)envp,
                        true);
}

void __attribute__((constructor)) Infect(void)
{
    gum_init_embedded();

    GumInterceptor *interceptor = gum_interceptor_obtain();

    gum_interceptor_begin_transaction(interceptor);

    gum_interceptor_replace(
        interceptor,
        (gpointer)gum_module_find_export_by_name(NULL, "posix_spawn"),
        (gpointer)SpawnNew,
        NULL,
        (gpointer *)&SpawnOld);

    gum_interceptor_replace(
        interceptor,
        (gpointer)gum_module_find_export_by_name(NULL, "posix_spawnp"),
        (gpointer)SpawnPNew,
        NULL,
        (gpointer *)&SpawnPOld);

    gum_interceptor_end_transaction(interceptor);
}
