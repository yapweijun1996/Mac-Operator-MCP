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

static BOOL protectedGuiSession(NSString *bundleId) {
  return [@[@"com.apple.loginwindow", @"com.apple.SecurityAgent", @"com.apple.securityagent"] containsObject:bundleId ?: @""];
}

// A timer keeps an otherwise empty run loop alive; uptime bounds the whole transition.
static BOOL pollGuiState(NSTimeInterval deadline, BOOL (^readback)(void)) {
  while (NSProcessInfo.processInfo.systemUptime < deadline) {
    if (readback()) return YES;
    NSTimeInterval remaining = deadline - NSProcessInfo.processInfo.systemUptime;
    if (remaining <= 0) break;
    NSTimeInterval interval = MIN(0.05, remaining);
    NSTimer *timer = [NSTimer timerWithTimeInterval:interval repeats:NO block:^(NSTimer *value) { (void)value; }];
    [NSRunLoop.currentRunLoop addTimer:timer forMode:NSDefaultRunLoopMode];
    [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:interval]];
    [timer invalidate];
  }
  return NO;
}

// Workspace activation and system-wide AX focus are independent observations.
static BOOL readGuiFrontmost(NSRunningApplication *app, NSString **reason) {
  NSRunningApplication *frontmost = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (protectedGuiSession(frontmost.bundleIdentifier)) { *reason = @"protected_session"; return NO; }
  if (app.terminated || frontmost.processIdentifier != app.processIdentifier ||
      ![frontmost.bundleIdentifier isEqualToString:app.bundleIdentifier] ||
      app.launchDate == nil || ![frontmost.launchDate isEqualToDate:app.launchDate]) {
    *reason = @"focused_app_mismatch"; return NO;
  }
  AXUIElementRef system = AXUIElementCreateSystemWide(); CFTypeRef focused = NULL; pid_t pid = -1;
  AXUIElementSetMessagingTimeout(system, 0.5);
  AXError error = AXUIElementCopyAttributeValue(system, kAXFocusedApplicationAttribute, &focused);
  if (error == kAXErrorSuccess && focused != NULL && CFGetTypeID(focused) == AXUIElementGetTypeID())
    error = AXUIElementGetPid((AXUIElementRef)focused, &pid);
  if (focused != NULL) CFRelease(focused);
  CFRelease(system);
  if (error != kAXErrorSuccess) { *reason = error == kAXErrorAPIDisabled ? @"accessibility_permission" : @"ax_enumeration_failed"; return NO; }
  if (pid != app.processIdentifier) {
    NSString *focusedBundle = pid > 0 ? [NSRunningApplication runningApplicationWithProcessIdentifier:pid].bundleIdentifier : nil;
    *reason = protectedGuiSession(focusedBundle) ? @"protected_session" : @"focused_app_mismatch"; return NO;
  }
  return YES;
}

static BOOL readGuiFocusedWindow(NSRunningApplication *app, id selected, NSString **reason) {
  if (!readGuiFrontmost(app, reason)) return NO;
  AXUIElementRef axApp = AXUIElementCreateApplication(app.processIdentifier); CFTypeRef focused = NULL;
  AXUIElementSetMessagingTimeout(axApp, 0.5);
  AXError error = AXUIElementCopyAttributeValue(axApp, kAXFocusedWindowAttribute, &focused);
  pid_t pid = -1;
  BOOL same = error == kAXErrorSuccess && focused != NULL && CFGetTypeID(focused) == AXUIElementGetTypeID() &&
    AXUIElementGetPid((AXUIElementRef)focused, &pid) == kAXErrorSuccess && pid == app.processIdentifier &&
    CFEqual((__bridge CFTypeRef)selected, focused);
  if (focused != NULL) CFRelease(focused);
  CFRelease(axApp);
  if (!same) *reason = error == kAXErrorAPIDisabled ? @"accessibility_permission" : @"focused_window_not_found";
  return same;
}

static id selectGuiAxWindow(NSRunningApplication *app, NSString *hint, NSString *expectedIdentity,
                            NSString **reason) {
  NSArray *windows = axWindows(app.processIdentifier, reason);
  if (windows == nil || windows.count == 0) return nil;
  AXUIElementRef axApp = AXUIElementCreateApplication(app.processIdentifier);
  AXUIElementSetMessagingTimeout(axApp, 0.5);
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
  if (selected == nil) *reason = error == kAXErrorSuccess || error == kAXErrorNoValue
    ? @"window_not_found" : @"ax_enumeration_failed";
  return selected;
}

static GuiWindowTarget *resolveGuiWindow(NSString *bundleId, NSString *hint, BOOL focus,
                                         NSString *expectedIdentity, NSString **reason) {
  if (!AXIsProcessTrusted()) { *reason = @"accessibility_permission"; return nil; }
  NSArray<NSRunningApplication *> *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleId];
  if (apps.count == 0) { *reason = @"app_not_running"; return nil; }
  NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 3.0;
  NSRunningApplication *app = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (protectedGuiSession(app.bundleIdentifier)) { *reason = @"protected_session"; return nil; }
  if (![app.bundleIdentifier isEqualToString:bundleId]) {
    if (!focus) { *reason = @"app_not_frontmost"; return nil; }
    if (apps.count != 1) { *reason = @"window_ambiguous"; return nil; }
    app = apps[0];
  }
  enableBrowserAccessibility(bundleId, app.processIdentifier);
  __block id selected = nil;
  __block NSString *selectionReason = @"window_not_found";
  if (focus) {
    // Launch verification proves process readiness; AX window publication may follow later.
    pollGuiState(deadline, ^BOOL {
      NSRunningApplication *frontmost = NSWorkspace.sharedWorkspace.frontmostApplication;
      if (protectedGuiSession(frontmost.bundleIdentifier)) { selectionReason = @"protected_session"; return YES; }
      NSRunningApplication *current = [NSRunningApplication runningApplicationWithProcessIdentifier:app.processIdentifier];
      if (app.terminated || current == nil || ![current.bundleIdentifier isEqualToString:bundleId] ||
          app.launchDate == nil || ![current.launchDate isEqualToDate:app.launchDate]) {
        selectionReason = @"app_not_running"; return YES;
      }
      selected = selectGuiAxWindow(app, hint, expectedIdentity, &selectionReason);
      return selected != nil || ![selectionReason isEqualToString:@"window_not_found"];
    });
  } else {
    selected = selectGuiAxWindow(app, hint, expectedIdentity, &selectionReason);
  }
  if (selected == nil) { *reason = selectionReason; return nil; }
  AXUIElementRef ax = (__bridge AXUIElementRef)selected;
  NSString *title = attributeText(ax, kAXTitleAttribute);
  if (sensitiveTitle(title)) { *reason = @"target_denied"; return nil; }
  if (title.length > 512) { *reason = @"ax_enumeration_failed"; return nil; }
  if (focus) {
    if (![app activateWithOptions:NSApplicationActivateIgnoringOtherApps]) { *reason = @"activation_failed"; return nil; }
    __block NSString *stateReason = @"focused_app_mismatch";
    if (!pollGuiState(deadline, ^BOOL { return readGuiFrontmost(app, &stateReason); })) {
      *reason = [stateReason isEqualToString:@"focused_app_mismatch"] ? @"frontmost_timeout" : stateReason; return nil;
    }
    if (attributeBool(ax, kAXMinimizedAttribute, NO) &&
        AXUIElementSetAttributeValue(ax, kAXMinimizedAttribute, kCFBooleanFalse) != kAXErrorSuccess) {
      *reason = @"window_unavailable"; return nil;
    }
    // Some ordinary windows do not implement AXRaise. Exact focus is the postcondition.
    if (!readGuiFocusedWindow(app, selected, &stateReason)) {
      if (![stateReason isEqualToString:@"focused_window_not_found"]) { *reason = stateReason; return nil; }
      if (AXUIElementPerformAction(ax, kAXRaiseAction) != kAXErrorSuccess) { *reason = @"activation_failed"; return nil; }
      AXUIElementSetAttributeValue(ax, kAXMainAttribute, kCFBooleanTrue);
    }
  }
  if (app.hidden || attributeBool(ax, kAXMinimizedAttribute, NO)) { *reason = @"window_unavailable"; return nil; }
  __block NSString *stateReason = @"focused_window_not_found";
  BOOL same = focus ? pollGuiState(deadline, ^BOOL { return readGuiFocusedWindow(app, selected, &stateReason); })
    : readGuiFocusedWindow(app, selected, &stateReason);
  if (!same) { *reason = stateReason; return nil; }
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
  if (!readGuiFocusedWindow(app, selected, reason)) return nil;
  GuiWindowTarget *target = [GuiWindowTarget new];
  target.application = app; target.axWindow = selected; target.cgWindow = cgWindow;
  target.windows = cgWindows; target.position = position; target.title = title; target.identity = identity;
  return target;
}
