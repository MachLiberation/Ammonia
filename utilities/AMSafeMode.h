// Sticky live Safe Mode quarantine for critical / AppKit hosts.

#ifndef AMSAFEMODE_H
#define AMSAFEMODE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool AMSafeModeIsActive(void);
bool AMSafeModeIsBootstrapDisabled(void);
void AMSafeModeEnter(const char *reason);
/* Unlinks sticky markers. Returns false if any unlink fails (e.g. EACCES). */
bool AMSafeModeExit(void);

/* Load fence: pending survives PAC/SIGKILL; next spawn promotes to sticky. */
void AMSafeModeArmPending(const char *host, const char *dylib);
void AMSafeModeDisarmPending(void);
bool AMSafeModePromotePendingIfNeeded(void);

bool AMSafeModeIsCriticalHost(const char *path_or_name);
void AMSafeModeInstallCrashHandlers(void);

#ifdef __cplusplus
}
#endif

#endif /* AMSAFEMODE_H */
