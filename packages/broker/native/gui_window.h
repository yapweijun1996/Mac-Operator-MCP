#pragma once

@interface GuiWindowTarget : NSObject
@property (nonatomic, strong) NSRunningApplication *application;
@property (nonatomic, strong) id axWindow;
@property (nonatomic, strong) NSDictionary *cgWindow;
@property (nonatomic, strong) NSArray<NSDictionary *> *windows;
@property (nonatomic) NSUInteger position;
@property (nonatomic, strong) NSString *title;
@property (nonatomic, strong) NSString *identity;
@end
@implementation GuiWindowTarget
@end

static BOOL axWindowBounds(AXUIElementRef window, CGRect *bounds) {
  CFTypeRef position = NULL, size = NULL;
  AXUIElementCopyAttributeValue(window, kAXPositionAttribute, &position);
  AXUIElementCopyAttributeValue(window, kAXSizeAttribute, &size);
  CGPoint point = CGPointZero; CGSize dimensions = CGSizeZero;
  BOOL valid = position != NULL && size != NULL && CFGetTypeID(position) == AXValueGetTypeID() &&
    CFGetTypeID(size) == AXValueGetTypeID() && AXValueGetValue(position, kAXValueCGPointType, &point) &&
    AXValueGetValue(size, kAXValueCGSizeType, &dimensions) && isfinite(point.x) && isfinite(point.y) &&
    isfinite(dimensions.width) && isfinite(dimensions.height) && dimensions.width > 0 && dimensions.height > 0;
  if (position != NULL) CFRelease(position);
  if (size != NULL) CFRelease(size);
  if (valid) *bounds = CGRectMake(point.x, point.y, dimensions.width, dimensions.height);
  return valid;
}

// AX and CG use global top-left screen coordinates. Titles are presentation text.
static NSDictionary *correlateWindow(NSArray<NSDictionary *> *windows, pid_t pid, CGRect axBounds,
                                     NSUInteger *position, NSString **reason) {
  NSDictionary *selected = nil;
  for (NSUInteger index = 0; index < windows.count; index++) {
    NSDictionary *candidate = windows[index]; CGRect bounds = CGRectZero;
    if ([candidate[(id)kCGWindowOwnerPID] intValue] != pid || [candidate[(id)kCGWindowLayer] intValue] != 0 ||
        (candidate[(id)kCGWindowIsOnscreen] != nil && ![candidate[(id)kCGWindowIsOnscreen] boolValue]) ||
        [candidate[(id)kCGWindowAlpha] doubleValue] < 0.01 ||
        !CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)candidate[(id)kCGWindowBounds], &bounds)) continue;
    if (fabs(bounds.origin.x - axBounds.origin.x) > 1 || fabs(bounds.origin.y - axBounds.origin.y) > 1 ||
        fabs(bounds.size.width - axBounds.size.width) > 1 || fabs(bounds.size.height - axBounds.size.height) > 1) continue;
    if (selected != nil) { *reason = @"window_ambiguous"; return nil; }
    selected = candidate; *position = index;
  }
  if (selected == nil) *reason = @"window_correlation_failed";
  return selected;
}

static NSArray *axWindows(pid_t pid, NSString **reason) {
  AXUIElementRef app = AXUIElementCreateApplication(pid);
  AXUIElementSetMessagingTimeout(app, 0.5);
  CFIndex count = 0; CFArrayRef raw = NULL;
  AXError error = AXUIElementGetAttributeValueCount(app, kAXWindowsAttribute, &count);
  if (error == kAXErrorSuccess && count > 0 && count <= 64)
    error = AXUIElementCopyAttributeValues(app, kAXWindowsAttribute, 0, count, &raw);
  CFRelease(app);
  if (error != kAXErrorSuccess || count > 64 || (count > 0 && raw == NULL)) {
    if (raw != NULL) CFRelease(raw);
    *reason = @"ax_enumeration_failed"; return nil;
  }
  NSArray *windows = raw == NULL ? @[] : [(__bridge NSArray *)raw copy];
  if (raw != NULL) CFRelease(raw);
  if (windows.count == 0) *reason = @"window_not_found";
  return windows;
}

static GuiWindowTarget *resolveGuiWindow(NSString *bundleId, NSString *hint, BOOL focus,
                                         NSString *expectedIdentity, NSString **reason) {
  if (!AXIsProcessTrusted()) { *reason = @"accessibility_permission"; return nil; }
  NSArray<NSRunningApplication *> *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleId];
  if (apps.count == 0) { *reason = @"app_not_running"; return nil; }
  NSRunningApplication *app = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (![app.bundleIdentifier isEqualToString:bundleId]) {
    if (!focus) { *reason = @"app_not_frontmost"; return nil; }
    if (apps.count != 1) { *reason = @"window_ambiguous"; return nil; }
    app = apps[0]; [app activateWithOptions:NSApplicationActivateIgnoringOtherApps];
    for (NSUInteger attempt = 0; attempt < 30; attempt++) {
      if (NSWorkspace.sharedWorkspace.frontmostApplication.processIdentifier == app.processIdentifier) break;
      [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
  }
  if (app.terminated || NSWorkspace.sharedWorkspace.frontmostApplication.processIdentifier != app.processIdentifier) {
    *reason = @"app_not_frontmost"; return nil;
  }
  enableBrowserAccessibility(bundleId, app.processIdentifier);
  NSArray *windows = axWindows(app.processIdentifier, reason);
  if (windows == nil || windows.count == 0) return nil;
  AXUIElementRef axApp = AXUIElementCreateApplication(app.processIdentifier);
  CFTypeRef focused = NULL;
  AXError error = AXUIElementCopyAttributeValue(axApp, kAXFocusedWindowAttribute, &focused);
  CFRelease(axApp);
  id selected = nil;
  for (id candidate in windows) {
    BOOL match = hint.length > 0 && expectedIdentity.length == 0
      ? [attributeText((__bridge AXUIElementRef)candidate, kAXTitleAttribute) isEqualToString:hint]
      : focused != NULL && CFEqual((__bridge CFTypeRef)candidate, focused);
    if (!match) continue;
    if (selected != nil) { if (focused != NULL) CFRelease(focused); *reason = @"window_ambiguous"; return nil; }
    selected = candidate;
  }
  if (focused != NULL) CFRelease(focused);
  if (selected == nil) { *reason = error == kAXErrorSuccess ? @"window_not_found" : @"ax_enumeration_failed"; return nil; }
  AXUIElementRef ax = (__bridge AXUIElementRef)selected;
  NSString *title = attributeText(ax, kAXTitleAttribute);
  if (sensitiveTitle(title)) { *reason = @"target_denied"; return nil; }
  if (title.length > 512) { *reason = @"ax_enumeration_failed"; return nil; }
  if (focus) {
    if (attributeBool(ax, kAXMinimizedAttribute, NO)) AXUIElementSetAttributeValue(ax, kAXMinimizedAttribute, kCFBooleanFalse);
    AXUIElementPerformAction(ax, kAXRaiseAction);
    AXUIElementSetAttributeValue(ax, kAXMainAttribute, kCFBooleanTrue);
  }
  if (app.hidden || attributeBool(ax, kAXMinimizedAttribute, NO)) { *reason = @"window_unavailable"; return nil; }
  BOOL same = NO;
  for (NSUInteger attempt = 0; attempt < (focus ? 30 : 1); attempt++) {
    axApp = AXUIElementCreateApplication(app.processIdentifier); focused = NULL;
    error = AXUIElementCopyAttributeValue(axApp, kAXFocusedWindowAttribute, &focused); CFRelease(axApp);
    same = error == kAXErrorSuccess && focused != NULL && CFEqual((__bridge CFTypeRef)selected, focused);
    if (focused != NULL) CFRelease(focused);
    if (same) break;
    if (focus) [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
  }
  if (!same) { *reason = @"focus_changed"; return nil; }
  title = attributeText(ax, kAXTitleAttribute);
  if (sensitiveTitle(title)) { *reason = @"target_denied"; return nil; }
  if (title.length > 512) { *reason = @"ax_enumeration_failed"; return nil; }
  CGRect bounds = CGRectZero;
  if (!axWindowBounds(ax, &bounds)) { *reason = @"ax_enumeration_failed"; return nil; }
  NSArray *cgWindows = CFBridgingRelease(CGWindowListCopyWindowInfo(
    kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID));
  if (cgWindows == nil || cgWindows.count > 4096) { *reason = @"window_correlation_failed"; return nil; }
  NSUInteger position = NSNotFound;
  NSDictionary *cgWindow = correlateWindow(cgWindows, app.processIdentifier, bounds, &position, reason);
  if (cgWindow == nil) return nil;
  if (app.launchDate == nil) { *reason = @"ax_enumeration_failed"; return nil; }
  NSString *identity = [NSString stringWithFormat:@"%d:%lld:%u", app.processIdentifier,
    (long long)(app.launchDate.timeIntervalSince1970 * 1000), [cgWindow[(id)kCGWindowNumber] unsignedIntValue]];
  if (expectedIdentity.length > 0 && ![identity isEqualToString:expectedIdentity]) { *reason = @"stale_target"; return nil; }
  GuiWindowTarget *target = [GuiWindowTarget new];
  target.application = app; target.axWindow = selected; target.cgWindow = cgWindow;
  target.windows = cgWindows; target.position = position; target.title = title; target.identity = identity;
  return target;
}
