import assert from "node:assert/strict";
import { before, after, test } from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

let directory, executable;
const options = { env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }, timeout: 30000, maxBuffer: 65536 };
before(async () => {
  if (process.platform !== "darwin") return;
  directory = await mkdtemp("/tmp/mop-desktop-app-tests-");
  executable = join(directory, "desktop-fixture");
  const source = join(directory, "fixture.m");
  await writeFile(source, `
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <assert.h>
static NSMutableDictionary *window, *field, *toolbar;
static NSArray *cgWindows;
static int posted = 0, pressed = 0;
static BOOL trusted = YES, offDesktop = NO, locked = NO, layoutChanged = NO, recording = YES;
static BOOL captureChangesLayout = NO, captureOpensSensitive = NO;
static NSInteger switchAfterPosts = -1;
static NSMutableDictionary *hit;
static NSSet *capturedBundles;
static BOOL captureDeniesOther = NO;
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
static FixtureApp *application, *other, *front, *dock;
@implementation FixtureApp
+ (NSArray *)runningApplicationsWithBundleIdentifier:(NSString *)bundle {
  return [bundle isEqualToString:application.bundleIdentifier] ? @[application] : @[];
}
+ (instancetype)runningApplicationWithProcessIdentifier:(pid_t)pid { return pid == application.processIdentifier ? application : (pid == 888 ? dock : other); }
- (BOOL)activateWithOptions:(NSApplicationActivationOptions)options { (void)options; front = self; return YES; }
@end
@interface FixtureWorkspace : NSObject
+ (instancetype)sharedWorkspace;
- (FixtureApp *)frontmostApplication;
@end
@implementation FixtureWorkspace
+ (instancetype)sharedWorkspace { static FixtureWorkspace *value; if (!value) value = [self new]; return value; }
- (FixtureApp *)frontmostApplication { return front; }
@end
static AXUIElementRef fakeApp(pid_t pid) { return (AXUIElementRef)CFBridgingRetain(@{@"kind":@"app", @"pid":@(pid)}); }
static AXUIElementRef fakeSystem(void) { return (AXUIElementRef)CFBridgingRetain(@{@"kind":@"system"}); }
static AXError fakeTimeout(AXUIElementRef element, float timeout) { (void)element; (void)timeout; return kAXErrorSuccess; }
static AXError fakeCopy(AXUIElementRef element, CFStringRef attribute, CFTypeRef *value) {
  NSDictionary *record = (__bridge NSDictionary *)element; id result = nil;
  if (CFEqual(attribute, kAXFocusedApplicationAttribute)) result = @{@"pid":@(front.processIdentifier)};
  else if (CFEqual(attribute, kAXFocusedWindowAttribute)) result = window;
  else if (CFEqual(attribute, kAXFocusedUIElementAttribute)) result = field;
  else result = record[(__bridge NSString *)attribute];
  *value = result == nil ? NULL : CFBridgingRetain(result);
  return result == nil ? kAXErrorNoValue : kAXErrorSuccess;
}
static AXError fakeCount(AXUIElementRef element, CFStringRef attribute, CFIndex *count) {
  if (CFEqual(attribute, kAXWindowsAttribute)) *count = 1;
  else *count = [((__bridge NSDictionary *)element)[(__bridge NSString *)attribute] count];
  return kAXErrorSuccess;
}
static AXError fakeValues(AXUIElementRef element, CFStringRef attribute, CFIndex start, CFIndex count, CFArrayRef *values) {
  NSArray *all = CFEqual(attribute,kAXWindowsAttribute) ? @[window] : ((__bridge NSDictionary *)element)[(__bridge NSString *)attribute];
  *values = (__bridge_retained CFArrayRef)[all subarrayWithRange:NSMakeRange(start,count)]; return kAXErrorSuccess;
}
static AXError fakePid(AXUIElementRef element, pid_t *pid) { *pid = [((__bridge NSDictionary *)element)[@"pid"] intValue]; return kAXErrorSuccess; }
static AXError fakeAction(AXUIElementRef element, CFStringRef action) {
  (void)element; if (CFEqual(action,kAXPressAction)) pressed++; return kAXErrorSuccess;
}
static AXError fakeSet(AXUIElementRef element, CFStringRef attribute, CFTypeRef value) {
  (void)element; (void)attribute; (void)value; return kAXErrorSuccess;
}
static AXError fakeHit(AXUIElementRef element, float x, float y, AXUIElementRef *output) {
  (void)element; (void)x; (void)y; *output=(AXUIElementRef)CFRetain((__bridge CFTypeRef)(hit ?: field)); return kAXErrorSuccess;
}
static CFArrayRef fakeCG(CGWindowListOption options, CGWindowID selected) { (void)options; (void)selected; return (__bridge_retained CFArrayRef)cgWindows; }
static void fakePost(CGEventTapLocation tap, CGEventRef event) { (void)tap; (void)event; posted++; if (posted==switchAfterPosts) front=other; }
static CGError fakeDisplays(uint32_t maximum, CGDirectDisplayID *displays, uint32_t *count) {
  assert(maximum >= 2); displays[0]=1; displays[1]=2; *count=2; return kCGErrorSuccess;
}
static CGRect fakeDisplayBounds(CGDirectDisplayID display) { return display==2 ? CGRectMake(-1280,0,1280,offDesktop ? 100 : (layoutChanged ? 901 : 900)) : CGRectMake(0,0,1440,900); }
static CGDirectDisplayID fakeMainDisplay(void) { return 1; }
static CFDictionaryRef fakeSession(void) { return (__bridge_retained CFDictionaryRef)@{(__bridge id)kCGSessionOnConsoleKey:@YES,@"CGSSessionScreenIsLocked":@(locked)}; }
@interface FixtureDisplay : NSObject
@property CGDirectDisplayID displayID;
@end
@implementation FixtureDisplay
@end
@interface FixtureCaptureApp : NSObject
@property NSString *bundleIdentifier;
@property pid_t processID;
@end
@implementation FixtureCaptureApp
@end
@interface FixtureCaptureWindow : NSObject
@property FixtureCaptureApp *owningApplication;
@property NSString *title;
@property NSInteger windowLayer;
@end
@implementation FixtureCaptureWindow
@end
@interface FixtureContent : NSObject
@property NSArray *applications;
@property NSArray *displays;
@property NSArray *windows;
+ (void)getShareableContentExcludingDesktopWindows:(BOOL)excluded onScreenWindowsOnly:(BOOL)onscreen completionHandler:(void (^)(id,NSError *))callback;
@end
@implementation FixtureContent
+ (void)getShareableContentExcludingDesktopWindows:(BOOL)excluded onScreenWindowsOnly:(BOOL)onscreen completionHandler:(void (^)(id,NSError *))callback {
  (void)excluded; (void)onscreen; FixtureContent *content=[self new]; FixtureDisplay *first=[FixtureDisplay new],*second=[FixtureDisplay new];
  first.displayID=1; second.displayID=2; content.displays=@[first,second]; content.windows=@[];
  FixtureCaptureApp *allowed=[FixtureCaptureApp new],*blocked=[FixtureCaptureApp new],*safeDock=[FixtureCaptureApp new],*ordinaryOther=[FixtureCaptureApp new];
  allowed.bundleIdentifier=@"com.apple.TextEdit"; allowed.processID=485; blocked.bundleIdentifier=@"com.apple.Passwords"; blocked.processID=777;
  safeDock.bundleIdentifier=@"com.apple.dock"; safeDock.processID=888; ordinaryOther.bundleIdentifier=@"com.example.Other"; ordinaryOther.processID=999;
  FixtureCaptureWindow *sensitive=[FixtureCaptureWindow new],*protected=[FixtureCaptureWindow new],*unknown=[FixtureCaptureWindow new],*dockWindow=[FixtureCaptureWindow new];
  sensitive.owningApplication=allowed; sensitive.title=@"Passwords"; protected.owningApplication=blocked; protected.title=@"Protected";
  unknown.title=@"Unknown"; dockWindow.owningApplication=safeDock; dockWindow.title=@"Dock";
  content.windows=@[sensitive,protected,unknown,dockWindow]; content.applications=@[allowed,blocked,safeDock,ordinaryOther]; callback(content,nil);
}
@end
@interface FixtureFilter : NSObject
@property CGRect contentRect;
@property CGFloat pointPixelScale;
@property BOOL includeMenuBar;
- (instancetype)initWithDisplay:(SCDisplay *)display excludingWindows:(NSArray *)windows;
- (instancetype)initWithDesktopIndependentWindow:(SCWindow *)selected;
- (instancetype)initWithDisplay:(SCDisplay *)display excludingApplications:(NSArray *)applications exceptingWindows:(NSArray *)windows;
@end
@implementation FixtureFilter
- (instancetype)initWithDisplay:(SCDisplay *)display excludingApplications:(NSArray *)applications exceptingWindows:(NSArray *)windows {
  (void)windows; NSMutableSet *bundles=[NSMutableSet set]; for (FixtureCaptureApp *app in applications) [bundles addObject:app.bundleIdentifier];
  assert([bundles containsObject:@"com.apple.Passwords"]); assert(![bundles containsObject:@"com.apple.TextEdit"]); assert(![bundles containsObject:@"com.apple.dock"]);
  assert([bundles containsObject:@"com.example.Other"]==captureDeniesOther);
  assert(windows.count==2); for (FixtureCaptureWindow *window in windows) assert(![window.owningApplication.bundleIdentifier isEqualToString:@"com.apple.Passwords"]);
  capturedBundles=bundles;
  return [self initWithDisplay:display excludingWindows:@[]];
}
- (instancetype)initWithDisplay:(SCDisplay *)display excludingWindows:(NSArray *)windows { (void)windows; self=[super init]; self.contentRect=fakeDisplayBounds(display.displayID); self.pointPixelScale=1; return self; }
- (instancetype)initWithDesktopIndependentWindow:(SCWindow *)selected { (void)selected; self=[super init]; self.contentRect=CGRectMake(0,0,800,600); self.pointPixelScale=1; return self; }
@end
@interface FixtureConfiguration : NSObject
@property NSUInteger width;
@property NSUInteger height;
@property BOOL showsCursor;
@end
@implementation FixtureConfiguration
@end
@interface FixtureScreenshot : NSObject
+ (void)captureImageWithFilter:(id)filter configuration:(id)config completionHandler:(void (^)(CGImageRef,NSError *))callback;
@end
@implementation FixtureScreenshot
+ (void)captureImageWithFilter:(id)filter configuration:(id)config completionHandler:(void (^)(CGImageRef,NSError *))callback {
  (void)filter; (void)config;
  if (captureChangesLayout) layoutChanged=YES;
  if (captureOpensSensitive) other.bundleIdentifier=@"com.apple.Passwords";
  if (captureOpensSensitive) cgWindows=@[@{(id)kCGWindowOwnerPID:@999,(id)kCGWindowLayer:@0,(id)kCGWindowAlpha:@1,
    (id)kCGWindowBounds:CFBridgingRelease(CGRectCreateDictionaryRepresentation(CGRectMake(-1280,0,500,400)))}];
  CGColorSpaceRef colors=CGColorSpaceCreateDeviceRGB(); CGContextRef context=CGBitmapContextCreate(NULL,4,4,8,0,colors,kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colors); CGImageRef image=CGBitmapContextCreateImage(context); CGContextRelease(context); callback(image,nil); CGImageRelease(image);
}
@end
#define SCShareableContent FixtureContent
#define SCContentFilter FixtureFilter
#define SCStreamConfiguration FixtureConfiguration
#define SCScreenshotManager FixtureScreenshot
#define CGSessionCopyCurrentDictionary fakeSession
#define CGMainDisplayID fakeMainDisplay
#define CGPreflightScreenCaptureAccess() recording
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
#define AXUIElementPerformAction fakeAction
#define AXUIElementSetAttributeValue fakeSet
#define AXUIElementCopyElementAtPosition fakeHit
#define AXUIElementGetTypeID CFDictionaryGetTypeID
#define CGWindowListCopyWindowInfo fakeCG
#define CGEventPost fakePost
#define CGGetActiveDisplayList fakeDisplays
#define CGDisplayBounds fakeDisplayBounds
#define main guiAdapterMain
#import "${resolve("packages/broker/native/gui_vision.m")}"
#undef main
int main(int argc, const char **argv) { @autoreleasepool {
  assert(argc==2); NSString *scenario=[NSString stringWithUTF8String:argv[1]];
  application=[FixtureApp new]; application.bundleIdentifier=@"com.apple.TextEdit"; application.processIdentifier=485;
  application.launchDate=[NSDate dateWithTimeIntervalSince1970:1790918400];
  other=[FixtureApp new]; other.bundleIdentifier=@"com.example.Other"; other.processIdentifier=999; other.launchDate=application.launchDate; front=application;
  dock=[FixtureApp new]; dock.bundleIdentifier=@"com.apple.dock"; dock.processIdentifier=888; dock.launchDate=application.launchDate;
  CGPoint origin=CGPointMake(-1200,30); CGSize size=CGSizeMake(800,600);
  window=[@{@"pid":@485,(__bridge id)kAXTitleAttribute:@"Ordinary document",(__bridge id)kAXRoleAttribute:@"AXWindow",
    (__bridge id)kAXPositionAttribute:CFBridgingRelease(AXValueCreate(kAXValueCGPointType,&origin)),
    (__bridge id)kAXSizeAttribute:CFBridgingRelease(AXValueCreate(kAXValueCGSizeType,&size)),
    (__bridge id)kAXEnabledAttribute:@YES} mutableCopy];
  toolbar=[@{@"pid":@485,(__bridge id)kAXRoleAttribute:@"AXToolbar",(__bridge id)kAXParentAttribute:window} mutableCopy];
  field=[@{@"pid":@485,(__bridge id)kAXRoleAttribute:@"AXTextField",(__bridge id)kAXTitleAttribute:@"Address",
    (__bridge id)kAXEnabledAttribute:@YES,(__bridge id)kAXWindowAttribute:window,(__bridge id)kAXParentAttribute:toolbar} mutableCopy];
  window[(__bridge id)kAXChildrenAttribute]=@[field];
  window[(__bridge id)kAXParentAttribute]=@{@"pid":@485,(__bridge id)kAXRoleAttribute:@"AXApplication"};
  cgWindows=@[@{(id)kCGWindowOwnerPID:@485,(id)kCGWindowNumber:@46,(id)kCGWindowLayer:@0,(id)kCGWindowAlpha:@1,
    (id)kCGWindowIsOnscreen:@YES,(id)kCGWindowBounds:CFBridgingRelease(CGRectCreateDictionaryRepresentation(CGRectMake(-1200,30,800,600)))}];
  const char *identity="485:1790918400000:46";
  if ([scenario hasPrefix:@"desktop_"]) {
    NSString *reason=nil; NSSet *denied=[NSSet set]; GuiDesktopTarget *desktop=resolveGuiDesktop(@"display:2",@"",denied,NO,&reason);
    assert(desktop!=nil && [desktop.identity hasPrefix:@"desktop:2:"]);
    const char *token=desktop.identity.UTF8String,*manifest="[]";
    id otherRoot=@{@"pid":@999,(__bridge id)kAXRoleAttribute:@"AXApplication"};
    if ([scenario isEqualToString:@"desktop_identity"]) {
      assert(desktop.bounds.origin.x==-1280 && desktop.bounds.size.width==1280 && desktop.layoutHash.length==64);
      assert(desktopDeniedApplications("{}") == nil && desktopDeniedApplications("[1]") == nil && desktopDeniedApplications("[\\"app;bad\\"]") == nil);
      assert(desktopApplicationDenied(@"COM.APPLE.PASSWORDS",denied));
      return emit(@{@"status":@"ok",@"identity":desktop.identity});
    }
    if ([scenario isEqualToString:@"desktop_inspect"]) { const char *args[]={"gui","inspect","visual","dev.macoperator.desktop","display:2","10",manifest}; return executeGui(7,args); }
    if ([scenario isEqualToString:@"desktop_locked"]) locked=YES;
    if ([scenario isEqualToString:@"desktop_stale_layout"]) layoutChanged=YES;
    if ([scenario isEqualToString:@"desktop_stale_display"]) token=[[desktop.identity stringByReplacingOccurrencesOfString:@"desktop:2:" withString:@"desktop:99:"] UTF8String];
    if ([scenario isEqualToString:@"desktop_parent_missing"]) [field removeObjectForKey:(__bridge id)kAXParentAttribute];
    if ([scenario isEqualToString:@"desktop_sensitive_hit"]) field[(__bridge id)kAXSubroleAttribute]=@"AXSecureTextField";
    if ([scenario isEqualToString:@"desktop_named_sensitive_hit"]) field[(__bridge id)kAXTitleAttribute]=@"Passwords";
    if ([scenario isEqualToString:@"desktop_denied_hit"]) {
      manifest="[\\"com.example.Other\\"]"; hit=[@{@"pid":@999,(__bridge id)kAXRoleAttribute:@"AXButton",(__bridge id)kAXTitleAttribute:@"Allowed-looking",(__bridge id)kAXParentAttribute:otherRoot} mutableCopy];
    }
    if ([scenario isEqualToString:@"desktop_dock_hit"]) { other.bundleIdentifier=@"com.apple.dock"; hit=[@{@"pid":@999,(__bridge id)kAXRoleAttribute:@"AXDockItem",(__bridge id)kAXTitleAttribute:@"Downloads",(__bridge id)kAXParentAttribute:otherRoot} mutableCopy]; }
    if ([scenario isEqualToString:@"desktop_menu_hit"]) { other.bundleIdentifier=@"com.apple.systemuiserver"; hit=[@{@"pid":@999,(__bridge id)kAXRoleAttribute:@"AXMenuBarItem",(__bridge id)kAXTitleAttribute:@"Window",(__bridge id)kAXParentAttribute:otherRoot} mutableCopy]; }
    if ([scenario isEqualToString:@"desktop_background_hit"]) { hit=[@{@"pid":@999,(__bridge id)kAXRoleAttribute:@"AXWindow",(__bridge id)kAXTitleAttribute:@"Ordinary",(__bridge id)kAXParentAttribute:otherRoot} mutableCopy]; switchAfterPosts=2; }
    if ([scenario isEqualToString:@"desktop_denied_visible"]) manifest="[\\"com.apple.TextEdit\\"]";
    if ([scenario isEqualToString:@"desktop_sensitive_visible"]) application.bundleIdentifier=@"COM.APPLE.PASSWORDS";
    if ([scenario isEqualToString:@"desktop_capture_layout_race"]) captureChangesLayout=YES;
    if ([scenario isEqualToString:@"desktop_capture_sensitive_race"]) captureOpensSensitive=YES;
    if ([scenario hasPrefix:@"desktop_capture"]) {
      if ([scenario isEqualToString:@"desktop_capture_manifest"]) { captureDeniesOther=YES; manifest="[\\"com.example.Other\\"]"; }
      if ([scenario isEqualToString:@"desktop_capture_permission"]) recording=NO;
      const char *args[]={"gui","capture","screen","dev.macoperator.desktop","display:2",token,manifest}; return executeGui(7,args);
    }
    if ([scenario hasPrefix:@"desktop_keyboard"] || [scenario hasPrefix:@"desktop_type"]) {
      if ([scenario isEqualToString:@"desktop_keyboard_changed"] || [scenario isEqualToString:@"desktop_type_changed"]) front=other;
      if ([scenario isEqualToString:@"desktop_type_secure"]) field[(__bridge id)kAXSubroleAttribute]=@"AXSecureTextField";
      if ([scenario isEqualToString:@"desktop_type_focus_race"]) switchAfterPosts=2;
      if ([scenario hasPrefix:@"desktop_type"]) {
        const char *args[]={"gui","type","visual","dev.macoperator.desktop","display:2","VisualWindow","Desktop",token,manifest};
        int result=executeGui(9,args); assert(posted==([scenario isEqualToString:@"desktop_type"]?16:([scenario isEqualToString:@"desktop_type_focus_race"]?2:0))); return result;
      }
      const char *args[]={"gui","action","visual","dev.macoperator.desktop","display:2","key_press","0","0","0","0","ENTER","0",token,manifest};
      int result=executeGui(14,args); assert(posted==([scenario isEqualToString:@"desktop_keyboard"]?2:0)); return result;
    }
    const char *args[]={"gui","action","visual","dev.macoperator.desktop","display:2","click","-1100","200","0","0","","0",token,manifest};
    int result=executeGui(14,args);
    BOOL allowed=[@[@"desktop_pointer",@"desktop_dock_hit",@"desktop_menu_hit",@"desktop_background_hit"] containsObject:scenario];
    assert(posted==(allowed?2:0)); return result;
  }
  if ([scenario isEqualToString:@"guards"]) {
    for (NSString *bundle in @[@"com.apple.TextEdit",@"com.apple.finder",@"com.example.Electron",@"com.google.Chrome",@"com.apple.Safari"]) assert(isGuiApplicationBundle(bundle));
    for (NSString *bundle in @[@"com.apple.SecurityAgent",@"COM.APPLE.KEYCHAINACCESS",@"COM.APPLE.PASSWORDS",@"com.apple.SystemPreferences",@"com.apple.loginwindow",@"../bin/sh",@"com.example.App\\n",@"app;rm",@""]) assert(!isGuiApplicationBundle(bundle));
    assert(!isGuiApplicationBundle(nil));
    assert(!browserNavigationElement((__bridge AXUIElementRef)field,application.bundleIdentifier));
    assert(browserNavigationElement((__bridge AXUIElementRef)field,@"com.google.Chrome"));
    assert(browserNavigationElement((__bridge AXUIElementRef)field,@"com.apple.Safari"));
    assert(isDesktopPoint(CGPointMake(-1100,200)));
    assert(!isDesktopPoint(CGPointMake(-2000,200)));
    return emit(@{@"status":@"ok"});
  }
  if ([scenario isEqualToString:@"capabilities"]) { trusted=NO; const char *args[]={"gui","capabilities"}; return executeGui(2,args); }
  if ([scenario isEqualToString:@"focus"]) { front=other; const char *args[]={"gui","focus","visual","com.apple.TextEdit",""}; return executeGui(5,args); }
  if ([scenario isEqualToString:@"inspect"]) { const char *args[]={"gui","inspect","accessibility","com.apple.TextEdit","","10"}; return executeGui(6,args); }
  if ([scenario isEqualToString:@"background_inspect"]) {
    front=other; const char *args[]={"gui","inspect","accessibility","com.apple.TextEdit","","10"};
    int result=executeGui(6,args); assert(front==other && posted==0); return result;
  }
  if ([scenario isEqualToString:@"ax_action"]) {
    const char *args[]={"gui","ax_action","accessibility","com.apple.TextEdit","Ordinary document","0","AXTextField","Address","press",identity};
    int result=executeGui(10,args); assert(pressed==1 && posted==0); return result;
  }
  if ([scenario isEqualToString:@"pointer"]) {
    const char *args[]={"gui","action","visual","com.apple.TextEdit","Ordinary document","click","-1100","200","0","0","","0",identity};
    int result=executeGui(13,args); assert(posted==2); return result;
  }
  if ([scenario isEqualToString:@"outside_window"]) {
    const char *args[]={"gui","action","visual","com.apple.TextEdit","Ordinary document","move_pointer","-1250","200","0","0","","0",identity};
    int result=executeGui(13,args); assert(posted==0); return result;
  }
  if ([scenario isEqualToString:@"off_desktop"]) {
    offDesktop=YES;
    const char *args[]={"gui","action","visual","com.apple.TextEdit","Ordinary document","move_pointer","-1100","200","0","0","","0",identity};
    int result=executeGui(13,args); assert(posted==0); return result;
  }
  if ([scenario isEqualToString:@"type"]) {
    const char *args[]={"gui","type","visual","com.apple.TextEdit","Ordinary document","AXTextField","Address",identity};
    int result=executeGui(8,args); assert(posted==16); return result;
  }
  if ([scenario isEqualToString:@"secure_type"]) {
    field[(__bridge id)kAXSubroleAttribute]=@"AXSecureTextField";
    const char *args[]={"gui","type","visual","com.apple.TextEdit","Ordinary document","AXTextField","Address",identity};
    int result=executeGui(8,args); assert(posted==0); return result;
  }
  return 2;
} }
`);
  execFileSync("/usr/bin/clang", ["-fobjc-arc", "-fblocks", "-Wno-deprecated-declarations", "-framework", "AppKit", "-framework", "ApplicationServices", "-framework", "ScreenCaptureKit", source, "-o", executable], options);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

function run(scenario) {
  return JSON.parse(execFileSync(executable, [scenario], { ...options, input: JSON.stringify({ text: "ordinary", keys: [], submit: false }) }));
}
for (const scenario of ["focus", "inspect", "ax_action", "pointer", "type"]) {
  test(`native ordinary application ${scenario} retains window identity and secure boundaries`, { skip: process.platform !== "darwin" }, () => {
    const result = run(scenario);
    assert.equal(result.status, "ok");
    assert.equal(result.app_id, "bundle:com.apple.TextEdit");
    assert.equal(result.window_identity, "485:1790918400000:46");
    if (scenario === "inspect") {
      assert.equal(result.nodes.length, 2);
      assert.equal(result.nodes[0].browser_navigation, false);
    }
  });
}
test("native generic app admission preserves protected apps, bundle grammar and browser-only toolbar authority", { skip: process.platform !== "darwin" }, () => assert.equal(run("guards").status, "ok"));
test("native capabilities independently identify the ordinary application protocol", { skip: process.platform !== "darwin" }, () => {
  assert.deepEqual(run("capabilities"), { status: "ok", version: "0.3", features: { ordinary_apps: true, bounded_global_coordinates: true, desktop_surfaces: true } });
});
for (const [scenario, error] of [["outside_window", "outside_window"], ["off_desktop", "outside_window"], ["secure_type", "secure_target"], ["background_inspect", "app_not_frontmost"]]) {
  test(`native ordinary application refuses ${scenario} before input dispatch`, { skip: process.platform !== "darwin" }, () => assert.deepEqual(run(scenario), { status: "error", error }));
}

for (const scenario of ["desktop_pointer", "desktop_dock_hit", "desktop_menu_hit", "desktop_background_hit", "desktop_keyboard", "desktop_type", "desktop_inspect", "desktop_capture", "desktop_capture_manifest"]) {
  test(`native desktop surface safely supports ${scenario}`, { skip: process.platform !== "darwin" }, () => {
    const result = run(scenario);
    assert.equal(result.status, "ok");
    assert.equal(result.app_id, "bundle:dev.macoperator.desktop");
    assert.match(result.window_identity, /^desktop:2:[a-f0-9]{64}:485:1790918400000$/);
    if (scenario === "desktop_type") assert.equal(result.element_index, -1);
    if (scenario === "desktop_inspect") assert.deepEqual(result.nodes, []);
    if (scenario === "desktop_capture") {
      assert.equal(result.window_x, -1280);
      assert.equal(result.window_width, 1280);
      assert.equal(result.window_height, 900);
      assert.ok(result.image_base64.length > 100);
    }
  });
}
test("native desktop identities bind the entire active layout and strict signed deny manifest", { skip: process.platform !== "darwin" }, () => assert.match(run("desktop_identity").identity, /^desktop:2:[a-f0-9]{64}:485:1790918400000$/));
for (const [scenario, error] of [
  ["desktop_locked", "protected_session"], ["desktop_stale_layout", "stale_target"], ["desktop_stale_display", "stale_target"],
  ["desktop_parent_missing", "secure_target"], ["desktop_sensitive_hit", "secure_target"], ["desktop_named_sensitive_hit", "secure_target"], ["desktop_denied_hit", "target_denied"],
  ["desktop_denied_visible", "target_denied"], ["desktop_sensitive_visible", "target_denied"],
  ["desktop_keyboard_changed", "stale_target"], ["desktop_type_changed", "stale_target"], ["desktop_type_secure", "secure_target"],
  ["desktop_type_focus_race", "stale_target"], ["desktop_capture_permission", "screen_recording_permission"],
  ["desktop_capture_layout_race", "stale_target"], ["desktop_capture_sensitive_race", "sensitive_window_visible"]
]) {
  test(`native desktop surface rejects ${scenario} with a structured boundary`, { skip: process.platform !== "darwin" }, () => assert.deepEqual(run(scenario), { status: "error", error }));
}
