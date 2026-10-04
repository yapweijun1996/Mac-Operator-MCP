#import <AppKit/AppKit.h>
#import <libproc.h>
#include <limits.h>

static NSString *generation(pid_t pid) {
  struct proc_bsdinfo info = {0};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return nil;
  return [NSString stringWithFormat:@"%llu:%llu", (unsigned long long)info.pbi_start_tvsec,
    (unsigned long long)info.pbi_start_tvusec];
}
static int emit(NSDictionary *value) {
  NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
  if (data == nil) return 1;
  fwrite(data.bytes, 1, data.length, stdout); fputc('\n', stdout);
  return 0;
}
int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 2 && argc != 4) return 64;
    NSString *operation = [NSString stringWithUTF8String:argv[1]];
    // This test utility addresses Calculator only and never force-terminates it.
    NSString *bundle = @"com.apple.calculator";
    NSArray<NSRunningApplication *> *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:bundle];
    if ([operation isEqualToString:@"snapshot"] && argc == 2) {
      if (apps.count == 0) return emit(@{ @"running": @NO });
      if (apps.count != 1) return emit(@{ @"error": @"ambiguous_process" });
      NSRunningApplication *app = apps.firstObject;
      NSString *identity = generation(app.processIdentifier);
      if (identity == nil) return emit(@{ @"error": @"process_identity_unavailable" });
      return emit(@{ @"running": @YES, @"bundle_id": bundle, @"pid": @(app.processIdentifier), @"generation": identity });
    }
    if (![operation isEqualToString:@"terminate"] || argc != 4 || apps.count != 1) return emit(@{ @"error": @"process_identity_changed" });
    char *end = NULL; long expectedPid = strtol(argv[2], &end, 10);
    NSRunningApplication *app = apps.firstObject;
    NSString *expectedGeneration = [NSString stringWithUTF8String:argv[3]];
    if (end == NULL || *end != '\0' || expectedPid <= 0 || expectedPid > INT_MAX || app.processIdentifier != expectedPid ||
        ![generation(app.processIdentifier) isEqualToString:expectedGeneration]) return emit(@{ @"error": @"process_identity_changed" });
    BOOL accepted = [app terminate];
    NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 3.0;
    while (accepted && NSProcessInfo.processInfo.systemUptime < deadline &&
           [generation((pid_t)expectedPid) isEqualToString:expectedGeneration]) {
      [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }
    BOOL stopped = ![generation((pid_t)expectedPid) isEqualToString:expectedGeneration];
    return emit(@{ @"accepted": @(accepted), @"stopped": @(stopped), @"generation_matched": @YES });
  }
}
