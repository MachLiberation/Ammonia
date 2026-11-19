#import <Cocoa/Cocoa.h>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "ammonia.h"

#define AM_SAFEMODE_MARKER  SupportFolderP ".safemode"
#define AM_SAFEMODE_REASON  SupportFolderP ".safemode.reason"
#define AM_SAFEMODE_PENDING SupportFolderP ".safemode.pending"

@interface AMSafeModeAppDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, assign) BOOL shownThisEpisode;
- (void)pollSafeMode:(NSTimer *)timer;
- (void)presentAlertIfNeeded;
@end

static BOOL FileExists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

static NSString *ReadReason(void)
{
    NSString *text = [NSString stringWithContentsOfFile:@AM_SAFEMODE_REASON
                                               encoding:NSUTF8StringEncoding
                                                  error:nil];
    if (!text.length)
        return @"(no reason recorded)";
    return [text stringByTrimmingCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static BOOL UnlinkPath(const char *path)
{
    if (!path)
        return YES;
    if (unlink(path) == 0 || errno == ENOENT)
        return YES;
    return NO;
}

/*
 * Markers are often created by root-owned hosts. core/ must be world-writable
 * (package.sh chmod 777); if unlink still fails, escalate once via osascript.
 */
static BOOL ExitSafeMode(void)
{
    if (UnlinkPath(AM_SAFEMODE_MARKER) &&
        UnlinkPath(AM_SAFEMODE_PENDING) &&
        UnlinkPath(AM_SAFEMODE_REASON))
        return YES;

    NSString *script = [NSString stringWithFormat:
        @"do shell script \"rm -f '%s' '%s' '%s'\" with administrator privileges",
        AM_SAFEMODE_MARKER, AM_SAFEMODE_PENDING, AM_SAFEMODE_REASON];
    NSAppleScript *apple = [[NSAppleScript alloc] initWithSource:script];
    NSDictionary *error = nil;
    [apple executeAndReturnError:&error];
    if (error)
        return NO;

    return !FileExists(AM_SAFEMODE_MARKER) &&
           !FileExists(AM_SAFEMODE_PENDING) &&
           !FileExists(AM_SAFEMODE_REASON);
}

static NSImage *AmmoniaInjectorIcon(void)
{
    static NSImage *cached;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray<NSString *> *paths = @[
            [[NSBundle mainBundle] pathForResource:@"AppIcon" ofType:@"icns"] ?: @"",
            @SupportFolderP "gui/Ammonia Injector.app/Contents/Resources/AppIcon.icns",
        ];
        for (NSString *path in paths) {
            if (!path.length)
                continue;
            NSImage *img = [[NSImage alloc] initWithContentsOfFile:path];
            if (img.size.width > 1.0) {
                cached = img;
                break;
            }
        }
        if (!cached)
            cached = [NSApp applicationIconImage];
        if (cached)
            [NSApp setApplicationIconImage:cached];
    });
    return cached;
}

static void RevealTweaks(void)
{
    NSString *tweaks = @SupportFolderP "tweaks";
    if (![[NSWorkspace sharedWorkspace] selectFile:nil
                          inFileViewerRootedAtPath:tweaks]) {
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:tweaks
                                                          isDirectory:YES]];
    }
}

static void ShowAlert(AMSafeModeAppDelegate *delegate)
{
    NSString *body = [NSString stringWithFormat:
        @"Ammonia entered Safe Mode after a critical-host crash "
        @"(WindowServer / loginwindow / AppKit).\n\n"
        @"Tweaks are quarantined so you can fix or remove the bad dylib "
        @"without Recovery or toggling SIP.\n\n"
        @"Reason:\n%@\n\n"
        @"Exit Safe Mode, then relaunch WindowServer / apps to reload tweaks.",
        ReadReason()];

    [NSApp activateIgnoringOtherApps:YES];

    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Ammonia Safe Mode";
    alert.informativeText = body;
    alert.alertStyle = NSAlertStyleInformational;
    NSImage *icon = AmmoniaInjectorIcon();
    if (icon)
        alert.icon = icon;
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Exit Safe Mode"];
    [alert addButtonWithTitle:@"Reveal Tweaks"];

    NSModalResponse response = [alert runModal];

    if (response == NSAlertSecondButtonReturn) {
        BOOL cleared = ExitSafeMode();
        delegate.shownThisEpisode = NO;
        NSAlert *done = [[NSAlert alloc] init];
        if (cleared) {
            done.messageText = @"Safe Mode cleared";
            done.informativeText =
                @"Sticky quarantine removed. Restart WindowServer and apps "
                @"to load Ammonia tweaks again.";
        } else {
            done.messageText = @"Could not exit Safe Mode";
            done.informativeText =
                @"Failed to remove /private/var/ammonia/core/.safemode "
                @"(permission denied). Run:\n\n"
                @"sudo rm -f /private/var/ammonia/core/.safemode*";
            done.alertStyle = NSAlertStyleWarning;
            /* Keep episode sticky so the main alert can return. */
            delegate.shownThisEpisode = YES;
        }
        if (icon)
            done.icon = icon;
        [done addButtonWithTitle:@"OK"];
        [NSApp activateIgnoringOtherApps:YES];
        [done runModal];
        if (!cleared)
            delegate.shownThisEpisode = NO;
        return;
    }

    if (response == NSAlertThirdButtonReturn) {
        dispatch_async(dispatch_get_main_queue(), ^{
            RevealTweaks();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [delegate presentAlertIfNeeded];
            });
        });
        delegate.shownThisEpisode = NO;
    }
}

@implementation AMSafeModeAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    (void)notification;
    self.shownThisEpisode = NO;
    [NSTimer scheduledTimerWithTimeInterval:2.0
                                     target:self
                                   selector:@selector(pollSafeMode:)
                                   userInfo:nil
                                    repeats:YES];
    [self pollSafeMode:nil];
}

- (void)pollSafeMode:(NSTimer *)timer
{
    (void)timer;
    if (!FileExists(AM_SAFEMODE_MARKER)) {
        self.shownThisEpisode = NO;
        return;
    }
    [self presentAlertIfNeeded];
}

- (void)presentAlertIfNeeded
{
    if (!FileExists(AM_SAFEMODE_MARKER) || self.shownThisEpisode)
        return;
    self.shownThisEpisode = YES;
    ShowAlert(self);
}

@end

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        BOOL watch = NO, force = NO;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--watch") == 0)
                watch = YES;
            else if (strcmp(argv[i], "--force") == 0)
                force = YES;
            else if (strcmp(argv[i], "--exit") == 0) {
                ExitSafeMode();
                return 0;
            }
        }

        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        (void)AmmoniaInjectorIcon();

        if (!watch) {
            if (force || FileExists(AM_SAFEMODE_MARKER)) {
                AMSafeModeAppDelegate *delegate = [[AMSafeModeAppDelegate alloc] init];
                ShowAlert(delegate);
            }
            return 0;
        }

        AMSafeModeAppDelegate *delegate = [[AMSafeModeAppDelegate alloc] init];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
