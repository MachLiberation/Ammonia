#include "AMSafeMode.h"
#include "ammonia.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define AM_SAFEMODE_MARKER  SupportFolderP ".safemode"
#define AM_SAFEMODE_PENDING SupportFolderP ".safemode.pending"
#define AM_SAFEMODE_REASON  SupportFolderP ".safemode.reason"
#define AM_SAFEMODE_DISABLE SupportFolderP ".safemode.disable"
#define AM_SAFEMODE_HOSTS   SupportFolderP "ammonia_safemode.hosts"

static const char *kCriticalHosts[] = {
    "WindowServer", "loginwindow", "Dock", "SystemUIServer",
    "ControlCenter", "Finder", "WindowManager", "MenuBarAgent",
    "coreauthd", NULL
};

static const char *BasenameOf(const char *path)
{
    if (!path || !*path)
        return NULL;
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static bool FileExists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

static void WriteTextFile(const char *path, const char *text)
{
    if (!path)
        return;
    /* 0666 so the user LaunchAgent can replace/clear root-written markers. */
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) {
        syslog(LOG_ERR, "AMSafeMode: write %s: %s", path, strerror(errno));
        return;
    }
    (void)fchmod(fd, 0666);
    if (text && *text) {
        size_t len = strlen(text);
        (void)write(fd, text, len);
        if (text[len - 1] != '\n')
            (void)write(fd, "\n", 1);
    }
    close(fd);
}

static bool UnlinkQuiet(const char *path)
{
    if (!path)
        return true;
    if (unlink(path) == 0 || errno == ENOENT)
        return true;
    syslog(LOG_ERR, "AMSafeMode: unlink %s: %s", path, strerror(errno));
    return false;
}

bool AMSafeModeIsActive(void)
{
    return FileExists(AM_SAFEMODE_MARKER);
}

bool AMSafeModeIsBootstrapDisabled(void)
{
    return FileExists(AM_SAFEMODE_DISABLE);
}

void AMSafeModeEnter(const char *reason)
{
    WriteTextFile(AM_SAFEMODE_MARKER, "1");
    if (reason && *reason)
        WriteTextFile(AM_SAFEMODE_REASON, reason);
    unlink(AM_SAFEMODE_PENDING);
    syslog(LOG_WARNING, "AMSafeMode: entered (%s)",
           reason && *reason ? reason : "no reason");
}

bool AMSafeModeExit(void)
{
    bool ok = true;
    ok = UnlinkQuiet(AM_SAFEMODE_MARKER) && ok;
    ok = UnlinkQuiet(AM_SAFEMODE_PENDING) && ok;
    ok = UnlinkQuiet(AM_SAFEMODE_REASON) && ok;
    return ok;
}

void AMSafeModeArmPending(const char *host, const char *dylib)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "host=%s\ndylib=%s\npid=%d\ntime=%ld\n",
             host && *host ? host : "unknown",
             dylib && *dylib ? dylib : "unknown",
             (int)getpid(), (long)time(NULL));
    WriteTextFile(AM_SAFEMODE_PENDING, buf);
    WriteTextFile(AM_SAFEMODE_REASON, buf);
}

void AMSafeModeDisarmPending(void)
{
    unlink(AM_SAFEMODE_PENDING);
}

bool AMSafeModePromotePendingIfNeeded(void)
{
    if (AMSafeModeIsActive())
        return true;
    if (!FileExists(AM_SAFEMODE_PENDING))
        return false;

    char reason[1024] = {0};
    FILE *fp = fopen(AM_SAFEMODE_PENDING, "r");
    if (fp) {
        size_t n = fread(reason, 1, sizeof(reason) - 1, fp);
        reason[n] = '\0';
        fclose(fp);
    }
    if (!reason[0])
        snprintf(reason, sizeof(reason), "unclean critical-host death");
    AMSafeModeEnter(reason);
    return true;
}

bool AMSafeModeIsCriticalHost(const char *path_or_name)
{
    const char *base = BasenameOf(path_or_name);
    if (!base)
        return false;

    if (FileExists(AM_SAFEMODE_HOSTS)) {
        FILE *fp = fopen(AM_SAFEMODE_HOSTS, "r");
        if (fp) {
            char line[256];
            bool matched = false;
            while (fgets(line, sizeof(line), fp)) {
                char *p = line;
                while (*p == ' ' || *p == '\t')
                    p++;
                if (*p == '#' || *p == '\0' || *p == '\n')
                    continue;
                size_t len = strlen(p);
                while (len && (p[len - 1] == '\n' || p[len - 1] == '\r' ||
                               p[len - 1] == ' ' || p[len - 1] == '\t'))
                    p[--len] = '\0';
                if (strcmp(p, base) == 0) {
                    matched = true;
                    break;
                }
            }
            fclose(fp);
            return matched;
        }
    }

    for (const char **h = kCriticalHosts; *h; h++) {
        if (strcmp(*h, base) == 0)
            return true;
    }
    return false;
}

static void AMSafeModeSignalHandler(int sig)
{
    char reason[128];
    snprintf(reason, sizeof(reason), "signal %d in %s (pid %d)",
             sig, getprogname() ? getprogname() : "unknown", (int)getpid());
    AMSafeModeEnter(reason);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
    raise(sig);
}

void AMSafeModeInstallCrashHandlers(void)
{
    static bool installed = false;
    if (installed)
        return;

    stack_t alt = {0};
    alt.ss_sp = malloc(SIGSTKSZ);
    if (!alt.ss_sp)
        return;
    alt.ss_size = SIGSTKSZ;
    if (sigaltstack(&alt, NULL) != 0) {
        free(alt.ss_sp);
        return;
    }

    const int signals[] = {
        SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGBUS, SIGSEGV, SIGSYS
    };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = AMSafeModeSignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK | SA_RESETHAND;
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
        sigaction(signals[i], &sa, NULL);
    installed = true;
}
