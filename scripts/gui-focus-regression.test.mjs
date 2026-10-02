import { before, after, test } from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

let directory, executable;
const options = { timeout: 30000, maxBuffer: 16384 };
before(async () => {
  if (process.platform !== "darwin") return;
  directory = await mkdtemp("/tmp/mop-focus-tests-");
  executable = join(directory, "focus-fixture");
  const source = join(directory, "fixture.m");
  await writeFile(source, `
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <assert.h>
static NSMutableDictionary *windowA, *windowB;
static NSArray *fixtureWindows, *fixtureCG;
static id fixtureFocused;
static BOOL trusted = YES, activationAccepted = YES, independentMismatch = NO, neverActivate = NO;
static int activationCount = 0;
static double activationAt = 0, raiseAt = 0;
@interface FixtureApp : NSObject
@property NSString *bundleIdentifier;
@property pid_t processIdentifier;
@property NSDate *launchDate;
@property BOOL terminated;
@property BOOL hidden;
+ (NSArray *)runningApplicationsWithBundleIdentifier:(NSString *)bundle;
+ (instancetype)runningApplicationWithProcessIdentifier:(pid_t)pid;
- (BOOL)activateWithOptions:(NSApplicationActivationOptions)options;
@end
static FixtureApp *browser, *other, *front;
@implementation FixtureApp
+ (NSArray *)runningApplicationsWithBundleIdentifier:(NSString *)bundle {
  return [bundle isEqualToString:browser.bundleIdentifier] ? @[browser] : @[];
}
+ (instancetype)runningApplicationWithProcessIdentifier:(pid_t)pid { return pid == browser.processIdentifier ? browser : other; }
- (BOOL)activateWithOptions:(NSApplicationActivationOptions)options {
  (void)options; activationCount++; activationAt = NSProcessInfo.processInfo.systemUptime;
  return activationAccepted;
}
@end
@interface FixtureWorkspace : NSObject
+ (instancetype)sharedWorkspace;
- (FixtureApp *)frontmostApplication;
@end
@implementation FixtureWorkspace
+ (instancetype)sharedWorkspace { static FixtureWorkspace *value; if (!value) value = [self new]; return value; }
- (FixtureApp *)frontmostApplication {
  if (activationAccepted && !neverActivate && activationAt > 0 && NSProcessInfo.processInfo.systemUptime - activationAt >= 0.08) front = browser;
  return front;
}
@end
static AXUIElementRef fakeApp(pid_t pid) { return (AXUIElementRef)CFBridgingRetain(@{@"kind":@"app", @"pid":@(pid)}); }
static AXUIElementRef fakeSystem(void) { return (AXUIElementRef)CFBridgingRetain(@{@"kind":@"system"}); }
static AXError fakeTimeout(AXUIElementRef element, float timeout) { (void)element; (void)timeout; return kAXErrorSuccess; }
static AXError fakeCopy(AXUIElementRef element, CFStringRef attribute, CFTypeRef *value) {
  NSDictionary *record = (__bridge NSDictionary *)element; id result = nil;
  if (CFEqual(attribute, kAXFocusedApplicationAttribute)) result = @{@"pid":@(independentMismatch ? 999 : front.processIdentifier)};
  else if (CFEqual(attribute, kAXFocusedWindowAttribute)) {
    if (raiseAt > 0 && NSProcessInfo.processInfo.systemUptime - raiseAt >= 0.08) fixtureFocused = windowB;
    result = fixtureFocused;
  } else result = record[(__bridge NSString *)attribute];
  *value = result == nil ? NULL : CFBridgingRetain(result);
  return result == nil ? kAXErrorNoValue : kAXErrorSuccess;
}
static AXError fakeCount(AXUIElementRef app, CFStringRef attribute, CFIndex *count) {
  (void)app; (void)attribute; *count = fixtureWindows.count; return kAXErrorSuccess;
}
static AXError fakeValues(AXUIElementRef app, CFStringRef attribute, CFIndex start, CFIndex count, CFArrayRef *values) {
  (void)app; (void)attribute; *values = (__bridge_retained CFArrayRef)[fixtureWindows subarrayWithRange:NSMakeRange(start,count)]; return kAXErrorSuccess;
}
static AXError fakePid(AXUIElementRef element, pid_t *pid) { *pid = [((__bridge NSDictionary *)element)[@"pid"] intValue]; return kAXErrorSuccess; }
static AXError fakeRaise(AXUIElementRef element, CFStringRef action) {
  (void)action; if ((__bridge id)element == windowB) raiseAt = NSProcessInfo.processInfo.systemUptime; return kAXErrorSuccess;
}
static AXError fakeSet(AXUIElementRef element, CFStringRef attribute, CFTypeRef value) {
  (void)element; (void)attribute; (void)value; return kAXErrorSuccess;
}
static CFArrayRef fakeCG(CGWindowListOption options, CGWindowID window) {
  (void)options; (void)window; return (__bridge_retained CFArrayRef)fixtureCG;
}
static NSString *attributeText(AXUIElementRef element, CFStringRef attribute) {
  return ((__bridge NSDictionary *)element)[(__bridge NSString *)attribute] ?: @"";
}
static BOOL attributeBool(AXUIElementRef element, CFStringRef attribute, BOOL fallback) {
  id value = ((__bridge NSDictionary *)element)[(__bridge NSString *)attribute]; return value ? [value boolValue] : fallback;
}
static BOOL sensitiveTitle(NSString *title) { return [title containsString:@"Password"]; }
static void enableBrowserAccessibility(NSString *bundle, pid_t pid) { (void)bundle; (void)pid; }
#define NSRunningApplication FixtureApp
#define NSWorkspace FixtureWorkspace
#define AXIsProcessTrusted() trusted
#define AXUIElementCreateApplication fakeApp
#define AXUIElementCreateSystemWide fakeSystem
#define AXUIElementSetMessagingTimeout fakeTimeout
#define AXUIElementCopyAttributeValue fakeCopy
#define AXUIElementGetAttributeValueCount fakeCount
#define AXUIElementCopyAttributeValues fakeValues
#define AXUIElementGetPid fakePid
#define AXUIElementPerformAction fakeRaise
#define AXUIElementSetAttributeValue fakeSet
#define AXUIElementGetTypeID CFDictionaryGetTypeID
#define CGWindowListCopyWindowInfo fakeCG
#import "${resolve("packages/broker/native/gui_window.h")}"
static NSMutableDictionary *axWindow(NSString *title, CGPoint point) {
  CGSize size = CGSizeMake(800,600);
  return [@{@"pid":@485, (__bridge id)kAXTitleAttribute:title,
    (__bridge id)kAXPositionAttribute:CFBridgingRelease(AXValueCreate(kAXValueCGPointType,&point)),
    (__bridge id)kAXSizeAttribute:CFBridgingRelease(AXValueCreate(kAXValueCGSizeType,&size))} mutableCopy];
}
static NSDictionary *cgWindow(int number, CGPoint point) {
  return @{(id)kCGWindowOwnerPID:@485, (id)kCGWindowNumber:@(number), (id)kCGWindowLayer:@0,
    (id)kCGWindowAlpha:@1, (id)kCGWindowIsOnscreen:@YES,
    (id)kCGWindowBounds:CFBridgingRelease(CGRectCreateDictionaryRepresentation(CGRectMake(point.x,point.y,800,600)))};
}
int main(int argc, const char **argv) { @autoreleasepool {
  assert(argc == 2); NSString *scenario = [NSString stringWithUTF8String:argv[1]];
  browser = [FixtureApp new]; browser.bundleIdentifier = @"com.google.Chrome"; browser.processIdentifier = 485;
  browser.launchDate = [NSDate dateWithTimeIntervalSince1970:1790918400];
  other = [FixtureApp new]; other.bundleIdentifier = @"com.example.Normal"; other.processIdentifier = 999;
  other.launchDate = browser.launchDate; front = other;
  windowA = axWindow(@"Window A", CGPointMake(10,30)); windowB = axWindow(@"Window B", CGPointMake(50,70));
  fixtureWindows = @[windowB,windowA]; fixtureFocused = windowA;
  fixtureCG = @[cgWindow(47,CGPointMake(50,70)),cgWindow(46,CGPointMake(10,30))];
  NSString *reason = nil;
  if ([scenario isEqualToString:@"protected"]) {
    other.bundleIdentifier = @"com.apple.loginwindow";
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",YES,@"",&reason) == nil);
    assert([reason isEqualToString:@"protected_session"] && activationCount == 0);
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",NO,@"",&reason) == nil && [reason isEqualToString:@"protected_session"]);
    front = browser; independentMismatch = YES;
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",NO,@"",&reason) == nil && [reason isEqualToString:@"protected_session"]);
  } else if ([scenario isEqualToString:@"activation"]) {
    activationAccepted = NO;
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",YES,@"",&reason) == nil);
    assert([reason isEqualToString:@"activation_failed"] && activationCount == 1);
  } else if ([scenario isEqualToString:@"timeout"]) {
    neverActivate = YES; double start = NSProcessInfo.processInfo.systemUptime;
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",YES,@"",&reason) == nil);
    assert([reason isEqualToString:@"frontmost_timeout"]);
    double elapsed = NSProcessInfo.processInfo.systemUptime - start; assert(elapsed >= 2.9 && elapsed < 3.5);
  } else if ([scenario isEqualToString:@"independent"]) {
    front = browser; independentMismatch = YES;
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",NO,@"",&reason) == nil);
    assert([reason isEqualToString:@"focused_app_mismatch"]);
  } else if ([scenario isEqualToString:@"hint"]) {
    GuiWindowTarget *target = resolveGuiWindow(browser.bundleIdentifier,@"Window B",YES,@"",&reason);
    assert(target && target.axWindow == windowB && [target.identity hasSuffix:@":47"]);
    windowA[(__bridge id)kAXTitleAttribute] = @"Window B";
    assert(resolveGuiWindow(browser.bundleIdentifier,@"Window B",YES,@"",&reason) == nil && [reason isEqualToString:@"window_ambiguous"]);
  } else if ([scenario isEqualToString:@"cycles"]) {
    NSString *identity = nil;
    for (int cycle = 0; cycle < 20; cycle++) {
      front = other; activationAt = 0;
      GuiWindowTarget *target = resolveGuiWindow(browser.bundleIdentifier,@"",YES,@"",&reason);
      assert(target && target.axWindow == windowA && front == browser && activationCount == cycle + 1);
      if (!identity) identity = target.identity;
      assert([target.identity isEqualToString:identity]);
      windowA[(__bridge id)kAXTitleAttribute] = [NSString stringWithFormat:@"Changed title %d",cycle];
      target = resolveGuiWindow(browser.bundleIdentifier,@"",NO,identity,&reason);
      assert(target && target.axWindow == windowA && [target.identity isEqualToString:identity]);
    }
    assert(resolveGuiWindow(browser.bundleIdentifier,@"",NO,@"485:1790918400000:47",&reason) == nil && [reason isEqualToString:@"stale_target"]);
  } else if ([scenario isEqualToString:@"permission"]) {
    trusted = NO; assert(resolveGuiWindow(browser.bundleIdentifier,@"",YES,@"",&reason) == nil);
    assert([reason isEqualToString:@"accessibility_permission"] && activationCount == 0);
  } else return 2;
} return 0; }
`);
  execFileSync("/usr/bin/clang", ["-fobjc-arc", "-fblocks", "-Wno-deprecated-declarations", "-framework", "AppKit", "-framework", "ApplicationServices", source, "-o", executable], options);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });
for (const [scenario, name] of [
  ["protected", "locked or protected desktop denies focus and observe before activation"],
  ["activation", "rejected macOS activation is not reported as a missing window"],
  ["timeout", "accepted activation without frontmost transition reaches a monotonic bounded timeout"],
  ["independent", "Workspace focus alone cannot substitute for independent system AX application readback"],
  ["hint", "explicit window hint raises and verifies the exact window and rejects duplicate hints"],
  ["cycles", "20 delayed focus and observe cycles preserve window identity through title changes"],
  ["permission", "missing AX permission fails before any activation"]
]) test(name, { skip: process.platform !== "darwin" }, () => execFileSync(executable, [scenario], options));
