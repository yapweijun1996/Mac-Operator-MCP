import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

// This probe intentionally exposes no labels, text values, window titles, or pixels.
if (process.platform !== "darwin" || process.env.MOPS_REAL_GUI !== "1") {
  console.log(JSON.stringify({ schema_version: "0.1", status: "not-run", reason: process.platform !== "darwin" ? "unsupported-platform" : "MOPS_REAL_GUI=1-required" }));
  process.exitCode = 2;
} else {
  const directory = await mkdtemp("/tmp/mop-ax-metadata-");
  try {
    const source = join(directory, "probe.m"), executable = join(directory, "probe");
    await writeFile(source, String.raw`
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>

static BOOL knownTarget(NSString *bundle) {
  return [@[@"com.apple.TextEdit", @"com.apple.calculator"] containsObject:bundle ?: @""];
}
static BOOL protectedBundle(NSString *bundle) {
  return [@[@"com.apple.loginwindow", @"com.apple.securityagent"] containsObject:bundle.lowercaseString ?: @""];
}
static NSString *safeBundle(NSString *bundle) {
  return knownTarget(bundle) || protectedBundle(bundle) ? bundle : @"other";
}
static NSDictionary *appIdentity(NSRunningApplication *app) {
  if (app == nil) return @{@"available": @NO};
  return @{@"available": @YES, @"bundle_id": safeBundle(app.bundleIdentifier), @"pid": @(app.processIdentifier),
    @"launch_generation_ms": app.launchDate == nil ? (id)NSNull.null : @((long long)(app.launchDate.timeIntervalSince1970 * 1000)),
    @"hidden": @(app.hidden), @"terminated": @(app.terminated)};
}
static NSString *safeRoleText(AXUIElementRef element, CFStringRef attribute) {
  CFTypeRef raw = NULL; AXError error = AXUIElementCopyAttributeValue(element, attribute, &raw);
  NSString *value = @"unavailable";
  if (error == kAXErrorSuccess && raw != NULL && CFGetTypeID(raw) == CFStringGetTypeID()) {
    NSString *candidate = (__bridge NSString *)raw;
    NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:@"^AX[A-Za-z0-9]{1,62}$" options:0 error:nil];
    NSTextCheckingResult *match = [pattern firstMatchInString:candidate options:0 range:NSMakeRange(0, candidate.length)];
    value = match != nil && match.range.length == candidate.length ? [candidate copy] : @"unexpected";
  }
  if (raw != NULL) CFRelease(raw);
  return value;
}
static NSString *valueType(CFTypeRef value) {
  if (value == NULL) return @"none";
  CFTypeID type = CFGetTypeID(value);
  if (type == AXUIElementGetTypeID()) return @"AXUIElement";
  if (type == CFBooleanGetTypeID()) return @"CFBoolean";
  if (type == CFNumberGetTypeID()) return @"CFNumber";
  return @"other";
}
static NSDictionary *enabledMetadata(AXUIElementRef element) {
  CFTypeRef raw = NULL; AXError error = AXUIElementCopyAttributeValue(element, kAXEnabledAttribute, &raw);
  id value = NSNull.null;
  if (raw != NULL && CFGetTypeID(raw) == CFBooleanGetTypeID()) value = @(CFBooleanGetValue((CFBooleanRef)raw));
  else if (raw != NULL && CFGetTypeID(raw) == CFNumberGetTypeID()) {
    double numeric = 0;
    if (CFNumberGetValue((CFNumberRef)raw, kCFNumberDoubleType, &numeric) && (numeric == 0 || numeric == 1)) value = @(numeric == 1);
  }
  NSDictionary *result = @{@"error": @(error), @"type": valueType(raw), @"bool": value};
  if (raw != NULL) CFRelease(raw);
  return result;
}
static NSDictionary *valueSettableMetadata(AXUIElementRef element) {
  Boolean settable = false;
  AXError error = AXUIElementIsAttributeSettable(element, kAXValueAttribute, &settable);
  return @{@"error": @(error), @"bool": error == kAXErrorSuccess ? (id)@(settable != false) : NSNull.null};
}
static NSDictionary *elementMetadata(CFTypeRef raw, AXError error, pid_t expectedPid, AXUIElementRef focusedWindow) {
  NSMutableDictionary *result = [@{@"error": @(error), @"type": valueType(raw)} mutableCopy];
  if (error != kAXErrorSuccess || raw == NULL || CFGetTypeID(raw) != AXUIElementGetTypeID()) return result;
  AXUIElementRef element = (AXUIElementRef)raw; pid_t pid = -1;
  AXError ownerError = AXUIElementGetPid(element, &pid);
  result[@"owner_error"] = @(ownerError); result[@"owner_matches"] = @(ownerError == kAXErrorSuccess && pid == expectedPid);
  result[@"role"] = safeRoleText(element, kAXRoleAttribute); result[@"subrole"] = safeRoleText(element, kAXSubroleAttribute);
  result[@"enabled"] = enabledMetadata(element);
  result[@"value_settable"] = valueSettableMetadata(element);
  CFTypeRef window = NULL; AXError windowError = AXUIElementCopyAttributeValue(element, kAXWindowAttribute, &window);
  NSMutableDictionary *windowResult = [@{@"error": @(windowError), @"type": valueType(window)} mutableCopy];
  if (windowError == kAXErrorSuccess && window != NULL && CFGetTypeID(window) == AXUIElementGetTypeID()) {
    pid_t windowPid = -1; AXError pidError = AXUIElementGetPid((AXUIElementRef)window, &windowPid);
    windowResult[@"owner_error"] = @(pidError); windowResult[@"owner_matches"] = @(pidError == kAXErrorSuccess && windowPid == expectedPid);
    windowResult[@"matches_focused_window"] = @(focusedWindow != NULL && CFEqual(window, focusedWindow));
  }
  result[@"window"] = windowResult;
  if (window != NULL) CFRelease(window);
  return result;
}
static NSDictionary *applicationMetadata(NSRunningApplication *app) {
  NSMutableDictionary *result = [appIdentity(app) mutableCopy];
  if (app == nil) return result;
  AXUIElementRef axApp = AXUIElementCreateApplication(app.processIdentifier);
  AXUIElementSetMessagingTimeout(axApp, 0.3);
  CFTypeRef window = NULL, element = NULL; CFIndex count = 0;
  AXError countError = AXUIElementGetAttributeValueCount(axApp, kAXWindowsAttribute, &count);
  AXError windowError = AXUIElementCopyAttributeValue(axApp, kAXFocusedWindowAttribute, &window);
  AXError elementError = AXUIElementCopyAttributeValue(axApp, kAXFocusedUIElementAttribute, &element);
  AXUIElementRef focusedWindow = window != NULL && CFGetTypeID(window) == AXUIElementGetTypeID() ? (AXUIElementRef)window : NULL;
  result[@"window_count_error"] = @(countError); result[@"window_count"] = @(count);
  result[@"focused_window"] = elementMetadata(window, windowError, app.processIdentifier, focusedWindow);
  result[@"focused_element"] = elementMetadata(element, elementError, app.processIdentifier, focusedWindow);
  if (window != NULL) CFRelease(window);
  if (element != NULL) CFRelease(element);
  CFRelease(axApp);
  return result;
}
static NSDictionary *frontmostMetadata(void) {
  NSMutableDictionary *result = [@{@"workspace": appIdentity(NSWorkspace.sharedWorkspace.frontmostApplication)} mutableCopy];
  AXUIElementRef system = AXUIElementCreateSystemWide(); AXUIElementSetMessagingTimeout(system, 0.3);
  CFTypeRef focused = NULL; AXError error = AXUIElementCopyAttributeValue(system, kAXFocusedApplicationAttribute, &focused);
  NSMutableDictionary *ax = [@{@"error": @(error), @"type": valueType(focused)} mutableCopy];
  if (error == kAXErrorSuccess && focused != NULL && CFGetTypeID(focused) == AXUIElementGetTypeID()) {
    pid_t pid = -1; AXError pidError = AXUIElementGetPid((AXUIElementRef)focused, &pid);
    ax[@"owner_error"] = @(pidError); ax[@"pid"] = @(pid);
    ax[@"bundle_id"] = safeBundle([NSRunningApplication runningApplicationWithProcessIdentifier:pid].bundleIdentifier);
  }
  result[@"system_ax"] = ax;
  if (focused != NULL) CFRelease(focused);
  CFRelease(system);
  return result;
}
static BOOL safeSession(NSDictionary *frontmost) {
  NSDictionary *workspace = frontmost[@"workspace"], *ax = frontmost[@"system_ax"];
  return [workspace[@"available"] boolValue] && !protectedBundle(workspace[@"bundle_id"]) &&
    [ax[@"type"] isEqualToString:@"AXUIElement"] && [ax[@"error"] intValue] == kAXErrorSuccess &&
    ax[@"owner_error"] != nil && [ax[@"owner_error"] intValue] == kAXErrorSuccess && [ax[@"pid"] intValue] > 0 &&
    ax[@"bundle_id"] != nil && !protectedBundle(ax[@"bundle_id"]);
}
static BOOL exactAppFocus(NSRunningApplication *app, NSDictionary *frontmost) {
  NSDictionary *workspace = frontmost[@"workspace"], *ax = frontmost[@"system_ax"];
  return safeSession(frontmost) && [workspace[@"pid"] intValue] == app.processIdentifier &&
    [workspace[@"bundle_id"] isEqualToString:app.bundleIdentifier] && [ax[@"pid"] intValue] == app.processIdentifier;
}
static void runloopTick(NSTimeInterval deadline) {
  NSTimeInterval interval = MIN(0.05, MAX(0, deadline - NSProcessInfo.processInfo.systemUptime));
  if (interval <= 0) return;
  NSTimer *timer = [NSTimer timerWithTimeInterval:interval repeats:NO block:^(NSTimer *value) { (void)value; }];
  [NSRunLoop.currentRunLoop addTimer:timer forMode:NSDefaultRunLoopMode];
  [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:interval]]; [timer invalidate];
}
static NSDictionary *calculatorActivation(BOOL metadataOnly) {
  NSMutableDictionary *result = [@{@"attempted": @NO, @"before_frontmost": frontmostMetadata()} mutableCopy];
  NSArray *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.calculator"];
  if (metadataOnly) { result[@"reason"] = @"metadata-only"; return result; }
  if (!AXIsProcessTrusted() || !safeSession(result[@"before_frontmost"])) { result[@"reason"] = @"permission-or-session-boundary"; return result; }
  if (apps.count != 1) { result[@"reason"] = @"calculator-process-not-unique"; return result; }
  NSRunningApplication *app = apps[0]; NSDate *generation = app.launchDate;
  if (app.terminated || generation == nil) { result[@"reason"] = @"calculator-process-not-ready"; return result; }
  AXUIElementRef axApp = AXUIElementCreateApplication(app.processIdentifier); AXUIElementSetMessagingTimeout(axApp, 0.3);
  CFTypeRef raw = NULL; AXError windowError = AXUIElementCopyAttributeValue(axApp, kAXFocusedWindowAttribute, &raw); CFRelease(axApp);
  result[@"window_selection_error"] = @(windowError);
  pid_t owner = -1;
  if (windowError != kAXErrorSuccess || raw == NULL || CFGetTypeID(raw) != AXUIElementGetTypeID() ||
      AXUIElementGetPid((AXUIElementRef)raw, &owner) != kAXErrorSuccess || owner != app.processIdentifier ||
      ![safeRoleText((AXUIElementRef)raw, kAXRoleAttribute) isEqualToString:@"AXWindow"] ||
      ![safeRoleText((AXUIElementRef)raw, kAXSubroleAttribute) isEqualToString:@"AXStandardWindow"]) {
    if (raw != NULL) CFRelease(raw); result[@"reason"] = @"calculator-ordinary-window-unproven"; return result;
  }
  result[@"attempted"] = @YES;
  BOOL accepted = [app activateWithOptions:NSApplicationActivateIgnoringOtherApps]; result[@"activation_accepted"] = @(accepted);
  NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 3.0;
  NSDictionary *frontmost = frontmostMetadata();
  while (accepted && safeSession(frontmost) && !exactAppFocus(app, frontmost) && NSProcessInfo.processInfo.systemUptime < deadline) {
    runloopTick(deadline); frontmost = frontmostMetadata();
  }
  result[@"after_activation_frontmost"] = frontmost; result[@"after_activation"] = applicationMetadata(app);
  NSRunningApplication *current = [NSRunningApplication runningApplicationWithProcessIdentifier:app.processIdentifier];
  AXUIElementRef readbackApp = AXUIElementCreateApplication(app.processIdentifier); AXUIElementSetMessagingTimeout(readbackApp, 0.3);
  CFTypeRef readbackWindow = NULL;
  AXError readbackError = AXUIElementCopyAttributeValue(readbackApp, kAXFocusedWindowAttribute, &readbackWindow); CFRelease(readbackApp);
  BOOL exactWindow = readbackError == kAXErrorSuccess && readbackWindow != NULL &&
    CFGetTypeID(readbackWindow) == AXUIElementGetTypeID() && CFEqual(raw, readbackWindow);
  result[@"exact_window_focused"] = @(exactWindow);
  if (readbackWindow != NULL) CFRelease(readbackWindow);
  if (exactAppFocus(app, frontmost) && !app.terminated && [current.bundleIdentifier isEqualToString:app.bundleIdentifier] &&
      [current.launchDate isEqualToDate:generation] && exactWindow) {
    result[@"raise_attempted"] = @YES; result[@"raise_error"] = @(AXUIElementPerformAction((AXUIElementRef)raw, kAXRaiseAction));
    result[@"after_raise_frontmost"] = frontmostMetadata(); result[@"after_raise"] = applicationMetadata(app);
  } else { result[@"raise_attempted"] = @NO; result[@"reason"] = @"calculator-focus-or-session-unproven"; }
  CFRelease(raw); return result;
}
int main(int argc, const char *argv[]) { @autoreleasepool {
  BOOL metadataOnly = argc == 2 && strcmp(argv[1], "--metadata-only") == 0;
  if (argc > 2 || (argc == 2 && !metadataOnly)) return 2;
  // Match the production AppKit lifecycle without requesting activation of this probe.
  [NSApplication sharedApplication];
  [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
  [NSApp finishLaunching];
  NSMutableArray *apps = [NSMutableArray new];
  for (NSString *bundle in @[@"com.apple.TextEdit", @"com.apple.calculator"]) {
    NSArray *running = [NSRunningApplication runningApplicationsWithBundleIdentifier:bundle];
    NSMutableDictionary *record = [@{@"bundle_id": bundle, @"running_count": @(running.count)} mutableCopy];
    if (running.count == 1) record[@"metadata"] = applicationMetadata(running[0]);
    [apps addObject:record];
  }
  NSDictionary *report = @{@"schema_version": @"0.1", @"status": @"observed", @"accessibility_trusted": @(AXIsProcessTrusted()),
    @"frontmost": frontmostMetadata(), @"apps": apps, @"calculator_activation": calculatorActivation(metadataOnly)};
  NSData *output = [NSJSONSerialization dataWithJSONObject:report options:0 error:nil];
  if (output == nil) return 1; fwrite(output.bytes, 1, output.length, stdout); fputc('\n', stdout); return 0;
}}
`);
    const options = { timeout: 30_000, maxBuffer: 65_536, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR: directory } };
    execFileSync("/usr/bin/clang", ["-fobjc-arc", "-fblocks", "-Wno-deprecated-declarations", "-framework", "AppKit", "-framework", "ApplicationServices", source, "-o", executable], options);
    const args = process.argv.slice(2);
    if (args.length > 1 || (args.length === 1 && args[0] !== "--metadata-only")) throw new Error("Only --metadata-only is supported");
    const report = JSON.parse(execFileSync(executable, args, options).toString("utf8"));
    console.log(JSON.stringify({ ...report, environment: { platform: process.platform, architecture: process.arch, node: process.versions.node, macos: execFileSync("/usr/bin/sw_vers", ["-productVersion"], options).toString("utf8").trim() } }));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
