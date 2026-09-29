#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import "gui_transport.h"

static int emit(NSDictionary *value) {
  NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
  if (data == nil) return 1;
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

static int fail(NSString *reason) {
  return emit(@{ @"status": @"error", @"error": reason });
}

static BOOL sensitiveTitle(NSString *title) {
  NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
    @"(?i)\\b(password|passcode|credential|security|privacy|private key|sign in|log in|two.factor|verification code)\\b"
    options:0 error:nil];
  return [pattern firstMatchInString:title options:0 range:NSMakeRange(0, title.length)] != nil;
}

static NSData *jpegForImage(CGImageRef image, NSUInteger maxEdge) {
  size_t width = CGImageGetWidth(image);
  size_t height = CGImageGetHeight(image);
  double scale = MIN(1.0, (double)maxEdge / (double)MAX(width, height));
  size_t outputWidth = MAX(1, (size_t)floor(width * scale));
  size_t outputHeight = MAX(1, (size_t)floor(height * scale));
  CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
  CGContextRef context = CGBitmapContextCreate(NULL, outputWidth, outputHeight, 8, 0,
    colorSpace, (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
  CGColorSpaceRelease(colorSpace);
  if (context == NULL) return nil;
  CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
  CGContextDrawImage(context, CGRectMake(0, 0, outputWidth, outputHeight), image);
  CGImageRef scaled = CGBitmapContextCreateImage(context);
  CGContextRelease(context);
  if (scaled == NULL) return nil;
  NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:scaled];
  CGImageRelease(scaled);
  for (NSNumber *quality in @[@0.65, @0.48, @0.32]) {
    NSData *data = [bitmap representationUsingType:NSBitmapImageFileTypeJPEG
      properties:@{ NSImageCompressionFactor: quality }];
    if (data != nil && data.length <= 480000) return data;
  }
  return nil;
}

static BOOL parseNumber(const char *text, NSInteger min, NSInteger max, NSInteger *value) {
  if (text == NULL || text[0] == '\0') return NO;
  char *end = NULL;
  long parsed = strtol(text, &end, 10);
  if (*end != '\0' || parsed < min || parsed > max) return NO;
  *value = parsed;
  return YES;
}

static NSString *attributeText(AXUIElementRef element, CFStringRef attribute) {
  CFTypeRef value = NULL;
  if (AXUIElementCopyAttributeValue(element, attribute, &value) != kAXErrorSuccess || value == NULL) return @"";
  NSString *text = CFGetTypeID(value) == CFStringGetTypeID() ? [(__bridge NSString *)value copy] : @"";
  CFRelease(value);
  return text;
}

static BOOL attributeBool(AXUIElementRef element, CFStringRef attribute, BOOL fallback) {
  CFTypeRef value = NULL;
  if (AXUIElementCopyAttributeValue(element, attribute, &value) != kAXErrorSuccess || value == NULL) return fallback;
  BOOL answer = CFGetTypeID(value) == CFBooleanGetTypeID() ? CFBooleanGetValue(value) : fallback;
  CFRelease(value);
  return answer;
}

static NSString *elementLabel(AXUIElementRef element) {
  for (id attribute in @[(__bridge id)kAXTitleAttribute,
                        (__bridge id)kAXDescriptionAttribute,
                        (__bridge id)kAXPlaceholderValueAttribute]) {
    NSString *value = attributeText(element, (__bridge CFStringRef)attribute);
    if (value.length > 0) return [value substringToIndex:MIN(value.length, 512)];
  }
  return @"";
}

static BOOL textRole(NSString *role) {
  return [@[@"AXTextField", @"AXTextArea", @"AXSearchField", @"AXComboBox"] containsObject:role];
}

static void enableBrowserAccessibility(NSString *bundleId, pid_t pid) {
  if (![bundleId isEqualToString:@"com.google.Chrome"] || !AXIsProcessTrusted()) return;
  AXUIElementRef app = AXUIElementCreateApplication(pid);
  // Chrome exposes its full tree on demand when an assistive client requests it.
  AXUIElementSetAttributeValue(app, CFSTR("AXEnhancedUserInterface"), kCFBooleanTrue);
  CFRelease(app);
}

static BOOL isPassThroughDockOverlay(NSString *bundleId, NSInteger layer,
                                     pid_t hitPid, pid_t browserPid) {
  return [bundleId isEqualToString:@"com.apple.dock"] && layer == 20 &&
    browserPid > 0 && hitPid == browserPid;
}

static pid_t systemHitPid(CGPoint point) {
  AXUIElementRef system = AXUIElementCreateSystemWide();
  AXUIElementRef hit = NULL;
  pid_t pid = -1;
  AXError error = AXUIElementCopyElementAtPosition(system, point.x, point.y, &hit);
  if (error == kAXErrorSuccess && hit != NULL) AXUIElementGetPid(hit, &pid);
  if (hit != NULL) CFRelease(hit);
  CFRelease(system);
  return pid;
}

static AXUIElementRef focusedElement(pid_t pid) {
  AXUIElementRef app = AXUIElementCreateApplication(pid);
  AXUIElementRef focused = NULL;
  AXError error = AXUIElementCopyAttributeValue(app, kAXFocusedUIElementAttribute, (CFTypeRef *)&focused);
  CFRelease(app);
  return error == kAXErrorSuccess ? focused : NULL;
}

static int inspectUi(NSString *bundleId, NSString *title, pid_t pid, NSInteger maxNodes) {
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  AXUIElementRef focused = focusedElement(pid);
  NSMutableArray *nodes = [NSMutableArray array];
  if (focused != NULL && maxNodes > 0) {
    NSString *role = attributeText(focused, kAXRoleAttribute);
    NSString *subrole = attributeText(focused, kAXSubroleAttribute);
    NSString *label = elementLabel(focused);
    BOOL secure = [subrole localizedCaseInsensitiveContainsString:@"secure"] ||
      [role localizedCaseInsensitiveContainsString:@"secure"] || sensitiveTitle(label);
    if (role.length > 0 && role.length <= 128) {
      [nodes addObject:@{ @"index": @0, @"role": role,
        @"label": secure ? @"" : label,
        @"enabled": @(attributeBool(focused, kAXEnabledAttribute, NO)),
        @"focused": @YES, @"secure": @(secure) }];
    }
    CFRelease(focused);
  }
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_index": @0, @"window_title": title, @"focused": @YES,
    @"nodes": nodes, @"truncated": @(maxNodes > 1) });
}

static BOOL postKey(CGKeyCode code, CGEventFlags flags) {
  for (NSNumber *down in @[@YES, @NO]) {
    CGEventRef event = CGEventCreateKeyboardEvent(NULL, code, down.boolValue);
    if (event == NULL) return NO;
    CGEventSetFlags(event, flags);
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
  }
  return YES;
}

static int typeIntoFocused(NSString *bundleId, NSString *title, pid_t pid, const char *expectedRole,
                           const char *expectedLabel) {
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  AXUIElementRef focused = focusedElement(pid);
  if (focused == NULL) return fail(@"stale_target");
  NSString *role = attributeText(focused, kAXRoleAttribute);
  NSString *subrole = attributeText(focused, kAXSubroleAttribute);
  NSString *label = elementLabel(focused);
  BOOL valid = textRole(role) && [role isEqualToString:[NSString stringWithUTF8String:expectedRole]] &&
    [label isEqualToString:[NSString stringWithUTF8String:expectedLabel]] &&
    ![subrole localizedCaseInsensitiveContainsString:@"secure"] && !sensitiveTitle(label) &&
    attributeBool(focused, kAXEnabledAttribute, NO);
  CFRelease(focused);
  if (!valid) return fail(@"secure_target");
  NSMutableData *input = [NSMutableData data];
  uint8_t buffer[4096];
  while (!feof(stdin) && input.length <= 40000) {
    size_t count = fread(buffer, 1, sizeof(buffer), stdin);
    if (count == 0) break;
    [input appendBytes:buffer length:count];
  }
  if (input.length > 40000) return fail(@"invalid_request");
  NSDictionary *request = [NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
  if (![request isKindOfClass:NSDictionary.class] || ![request[@"text"] isKindOfClass:NSString.class] ||
      ![request[@"keys"] isKindOfClass:NSArray.class] || ![request[@"submit"] isKindOfClass:NSNumber.class]) return fail(@"invalid_request");
  NSString *text = request[@"text"];
  NSArray *keys = request[@"keys"];
  if (text.length > 10000 || keys.count > 32) return fail(@"invalid_request");
  for (NSUInteger index = 0; index < text.length; index++) {
    if ([text characterAtIndex:index] == 0) return fail(@"invalid_request");
  }
  NSDictionary<NSString *, NSNumber *> *keyCodes = @{
    @"ENTER": @36, @"TAB": @48, @"ESCAPE": @53, @"ARROW_UP": @126,
    @"ARROW_DOWN": @125, @"ARROW_LEFT": @123, @"ARROW_RIGHT": @124,
    @"HOME": @115, @"END": @119
  };
  for (id key in keys) if (![key isKindOfClass:NSString.class] || keyCodes[key] == nil) return fail(@"invalid_request");
  for (NSUInteger offset = 0; offset < text.length;) {
    // Chrome accepts one Unicode scalar per keyboard event; preserve surrogate pairs.
    NSUInteger length = 1;
    if (CFStringIsSurrogateHighCharacter([text characterAtIndex:offset]) && offset + 1 < text.length &&
        CFStringIsSurrogateLowCharacter([text characterAtIndex:offset + 1])) length = 2;
    NSString *chunk = [text substringWithRange:NSMakeRange(offset, length)];
    offset += length;
    UniChar characters[2];
    [chunk getCharacters:characters range:NSMakeRange(0, chunk.length)];
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, 0, true);
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, 0, false);
    if (down == NULL || up == NULL) {
      if (down != NULL) CFRelease(down);
      if (up != NULL) CFRelease(up);
      return fail(@"execution_failed");
    }
    CGEventSetFlags(down, 0);
    CGEventSetFlags(up, 0);
    CGEventKeyboardSetUnicodeString(down, chunk.length, characters);
    CGEventKeyboardSetUnicodeString(up, chunk.length, characters);
    CGEventPost(kCGHIDEventTap, down);
    CGEventPost(kCGHIDEventTap, up);
    CFRelease(down); CFRelease(up);
  }
  for (NSString *key in keys) if (!postKey(keyCodes[key].unsignedShortValue, 0)) return fail(@"execution_failed");
  if ([request[@"submit"] boolValue] && !postKey(36, 0)) return fail(@"execution_failed");
  // Keep the event sender alive while WindowServer delivers the queued input.
  usleep(250000);
  if (![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqualToString:bundleId]) return fail(@"focus_changed");
  AXUIElementRef after = focusedElement(pid);
  BOOL focusConfirmed = after != NULL &&
    [attributeText(after, kAXRoleAttribute) isEqualToString:role] &&
    ![attributeText(after, kAXSubroleAttribute) localizedCaseInsensitiveContainsString:@"secure"] &&
    [elementLabel(after) isEqualToString:label];
  if (after != NULL) CFRelease(after);
  if (!focusConfirmed) return fail(@"focus_changed");
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_index": @0, @"window_title": title, @"element_index": @0, @"role": role,
    @"characters_accepted": @(text.length), @"keys_accepted": keys,
    @"submitted": request[@"submit"], @"focus_confirmed": @YES, @"secure": @NO });
}

static BOOL secureUiAt(pid_t pid, CGPoint point, BOOL focused) {
  AXUIElementRef app = AXUIElementCreateApplication(pid);
  AXUIElementRef element = NULL;
  AXError error = focused
    ? AXUIElementCopyAttributeValue(app, kAXFocusedUIElementAttribute, (CFTypeRef *)&element)
    : AXUIElementCopyElementAtPosition(app, point.x, point.y, &element);
  CFRelease(app);
  if (error != kAXErrorSuccess || element == NULL) return YES;
  NSString *identity = [NSString stringWithFormat:@"%@ %@ %@ %@",
    attributeText(element, kAXRoleAttribute), attributeText(element, kAXSubroleAttribute),
    attributeText(element, kAXTitleAttribute), attributeText(element, kAXDescriptionAttribute)];
  CFRelease(element);
  return sensitiveTitle(identity) || [identity localizedCaseInsensitiveContainsString:@"secure"];
}

static NSDictionary *browserWindow(NSArray<NSDictionary *> *windows, pid_t pid,
                                   NSString *windowHint, NSUInteger *position) {
  for (NSUInteger index = 0; index < windows.count; index++) {
    NSDictionary *window = windows[index];
    if ([window[(id)kCGWindowOwnerPID] intValue] != pid ||
        [window[(id)kCGWindowLayer] intValue] != 0 ||
        [window[(id)kCGWindowAlpha] doubleValue] < 0.01) continue;
    CGRect bounds = CGRectZero;
    if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)window[(id)kCGWindowBounds], &bounds) ||
        bounds.size.width < 320 || bounds.size.height < 240) continue;
    NSString *title = window[(id)kCGWindowName] ?: @"";
    if (title.length == 0 || sensitiveTitle(title) ||
        (windowHint.length > 0 && ![title isEqualToString:windowHint])) continue;
    *position = index;
    return window;
  }
  return nil;
}

static BOOL isExcludedScreenOverlay(NSString *bundleId, NSInteger layer) {
  return [bundleId isEqualToString:@"com.apple.dock"] && layer == 20;
}

static NSString *screenWindowBlockReason(BOOL ahead, NSInteger layer, CGRect browserBounds,
                                         CGRect otherBounds, BOOL sensitive) {
  BOOL visibleWindow = layer == 0 && (ahead || !CGRectContainsRect(browserBounds, otherBounds));
  BOOL largeOverlay = ahead && otherBounds.size.width > 100 && otherBounds.size.height > 80;
  if (!visibleWindow && !largeOverlay) return nil;
  if (sensitive) return @"sensitive_window_visible";
  return ahead ? @"screen_window_occluded" : @"screen_other_window_visible";
}

static CGImageRef captureImage(NSString *mode, CGWindowID windowId) {
  dispatch_semaphore_t ready = dispatch_semaphore_create(0);
  __block SCShareableContent *content = nil;
  [SCShareableContent getShareableContentExcludingDesktopWindows:YES onScreenWindowsOnly:YES
    completionHandler:^(SCShareableContent *value, NSError *error) {
      if (error == nil) content = value;
      dispatch_semaphore_signal(ready);
    }];
  if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0 || content == nil) return NULL;
  SCContentFilter *filter = nil;
  if ([mode isEqualToString:@"screen"]) {
    for (SCDisplay *display in content.displays) {
      if (display.displayID == CGMainDisplayID()) {
        // Exempt Dock's layer-20 surface only by excluding it from captured pixels too.
        NSMutableArray<SCWindow *> *excluded = [NSMutableArray array];
        for (SCWindow *window in content.windows) {
          if (isExcludedScreenOverlay(window.owningApplication.bundleIdentifier, window.windowLayer)) {
            [excluded addObject:window];
          }
        }
        filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:excluded];
        break;
      }
    }
  } else {
    for (SCWindow *window in content.windows) {
      if (window.windowID == windowId) {
        filter = [[SCContentFilter alloc] initWithDesktopIndependentWindow:window];
        break;
      }
    }
  }
  if (filter == nil) return NULL;
  SCStreamConfiguration *configuration = [[SCStreamConfiguration alloc] init];
  configuration.width = MAX(1, (size_t)ceil(filter.contentRect.size.width * filter.pointPixelScale));
  configuration.height = MAX(1, (size_t)ceil(filter.contentRect.size.height * filter.pointPixelScale));
  configuration.showsCursor = NO;
  dispatch_semaphore_t captured = dispatch_semaphore_create(0);
  __block CGImageRef image = NULL;
  [SCScreenshotManager captureImageWithFilter:filter configuration:configuration
    completionHandler:^(CGImageRef value, NSError *error) {
      if (error == nil && value != NULL) image = CGImageRetain(value);
      dispatch_semaphore_signal(captured);
    }];
  if (dispatch_semaphore_wait(captured, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) return NULL;
  return image;
}

static int performAction(NSString *bundleId, NSString *windowHint, NSArray<NSDictionary *> *windows,
                         NSRunningApplication *frontmost, int argc, const char *argv[]) {
  if (argc != 12) return fail(@"invalid_request");
  NSString *action = [NSString stringWithUTF8String:argv[5]];
  NSString *key = [NSString stringWithUTF8String:argv[10]];
  NSInteger x, y, dx, dy, waitMs;
  if (!parseNumber(argv[6], 0, 20000, &x) || !parseNumber(argv[7], 0, 20000, &y) ||
      !parseNumber(argv[8], -1000, 1000, &dx) || !parseNumber(argv[9], -1000, 1000, &dy) ||
      !parseNumber(argv[11], 0, 2000, &waitMs)) return fail(@"invalid_request");
  NSUInteger selectedPosition = NSNotFound;
  NSDictionary *selected = browserWindow(windows, frontmost.processIdentifier, windowHint, &selectedPosition);
  if (selected == nil || ![(selected[(id)kCGWindowName] ?: @"") isEqualToString:windowHint] ||
      sensitiveTitle(windowHint)) return fail(@"stale_target");
  CGRect bounds = CGRectZero;
  CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)selected[(id)kCGWindowBounds], &bounds);
  CGPoint point = CGPointMake(x, y);
  BOOL pointerAction = [@[@"click", @"double_click", @"right_click", @"move_pointer", @"scroll"] containsObject:action];
  if (pointerAction && !CGRectContainsPoint(bounds, point)) return fail(@"outside_window");
  for (NSUInteger index = 0; index < selectedPosition; index++) {
    NSDictionary *overlay = windows[index];
    if ([overlay[(id)kCGWindowOwnerPID] intValue] == frontmost.processIdentifier) continue;
    CGRect overlayBounds = CGRectZero;
    CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)overlay[(id)kCGWindowBounds], &overlayBounds);
    // Dock can publish a full-display layer-20 window that does not receive clicks.
    // Exempt it only when the system-wide hit test resolves to this browser.
    if (pointerAction && CGRectContainsPoint(overlayBounds, point) &&
        isPassThroughDockOverlay([NSRunningApplication runningApplicationWithProcessIdentifier:
          [overlay[(id)kCGWindowOwnerPID] intValue]].bundleIdentifier,
          [overlay[(id)kCGWindowLayer] integerValue], systemHitPid(point), frontmost.processIdentifier)) continue;
    if ((pointerAction && CGRectContainsPoint(overlayBounds, point)) ||
        (!pointerAction && [overlay[(id)kCGWindowLayer] intValue] == 0)) return fail(@"other_window_visible");
  }
  if (pointerAction && ![action isEqualToString:@"move_pointer"] && secureUiAt(frontmost.processIdentifier, point, NO)) return fail(@"secure_target");
  if (([action isEqualToString:@"key_press"] || [action isEqualToString:@"shortcut"]) &&
      secureUiAt(frontmost.processIdentifier, point, YES)) return fail(@"secure_target");
  CGEventRef event = NULL;
  if ([action isEqualToString:@"click"] || [action isEqualToString:@"double_click"] || [action isEqualToString:@"right_click"]) {
    BOOL right = [action isEqualToString:@"right_click"];
    NSInteger count = [action isEqualToString:@"double_click"] ? 2 : 1;
    for (NSInteger index = 1; index <= count; index++) {
      event = CGEventCreateMouseEvent(NULL, right ? kCGEventRightMouseDown : kCGEventLeftMouseDown,
        point, right ? kCGMouseButtonRight : kCGMouseButtonLeft);
      if (event == NULL) return fail(@"execution_failed");
      CGEventSetIntegerValueField(event, kCGMouseEventClickState, index);
      CGEventPost(kCGHIDEventTap, event); CFRelease(event);
      event = CGEventCreateMouseEvent(NULL, right ? kCGEventRightMouseUp : kCGEventLeftMouseUp,
        point, right ? kCGMouseButtonRight : kCGMouseButtonLeft);
      if (event == NULL) return fail(@"execution_failed");
      CGEventSetIntegerValueField(event, kCGMouseEventClickState, index);
      CGEventPost(kCGHIDEventTap, event); CFRelease(event);
    }
  } else if ([action isEqualToString:@"move_pointer"]) {
    event = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, point, kCGMouseButtonLeft);
    if (event == NULL) return fail(@"execution_failed");
    CGEventPost(kCGHIDEventTap, event); CFRelease(event);
  } else if ([action isEqualToString:@"scroll"]) {
    event = CGEventCreateScrollWheelEvent(NULL, kCGScrollEventUnitPixel, 2, (int32_t)dy, (int32_t)dx);
    if (event == NULL) return fail(@"execution_failed");
    CGEventSetLocation(event, point);
    CGEventPost(kCGHIDEventTap, event); CFRelease(event);
  } else if ([action isEqualToString:@"key_press"] || [action isEqualToString:@"shortcut"]) {
    NSDictionary<NSString *, NSNumber *> *keyCodes = @{
      @"ENTER": @36, @"TAB": @48, @"ESCAPE": @53, @"BACKSPACE": @51,
      @"ARROW_UP": @126, @"ARROW_DOWN": @125, @"ARROW_LEFT": @123,
      @"ARROW_RIGHT": @124, @"HOME": @115, @"END": @119,
      @"PAGE_UP": @116, @"PAGE_DOWN": @121, @"SPACE": @49,
      @"COMMAND_L": @37, @"COMMAND_R": @15, @"COMMAND_F": @3
    };
    BOOL shortcut = [action isEqualToString:@"shortcut"];
    if (shortcut != [key hasPrefix:@"COMMAND_"] || keyCodes[key] == nil) return fail(@"invalid_request");
    for (NSNumber *down in @[@YES, @NO]) {
      event = CGEventCreateKeyboardEvent(NULL, keyCodes[key].unsignedShortValue, down.boolValue);
      if (event == NULL) return fail(@"execution_failed");
      if (shortcut) CGEventSetFlags(event, kCGEventFlagMaskCommand);
      CGEventPost(kCGHIDEventTap, event); CFRelease(event);
    }
  } else if ([action isEqualToString:@"wait"]) {
    usleep((useconds_t)waitMs * 1000);
  } else return fail(@"invalid_request");
  // Event delivery is asynchronous and requires this authorized sender to stay alive.
  if (![action isEqualToString:@"wait"]) usleep(250000);
  if (![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqualToString:bundleId]) return fail(@"focus_changed");
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_title": windowHint, @"action": action, @"accepted": @YES, @"focused": @YES });
}

static int executeGui(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc == 2 && strcmp(argv[1], "permission") == 0) {
      return emit(@{ @"status": @"ok", @"accessibility": @(AXIsProcessTrusted()),
        @"screen_recording": @(CGPreflightScreenCaptureAccess()) });
    }
    if (argc == 2 && strcmp(argv[1], "request_accessibility") == 0) {
      NSDictionary *options = @{ (__bridge id)kAXTrustedCheckOptionPrompt: @YES };
      return emit(@{ @"status": @"ok", @"accessibility": @(AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options)) });
    }
    if (argc == 2 && strcmp(argv[1], "request_screen_recording") == 0) {
      return emit(@{ @"status": @"ok", @"screen_recording": @(CGRequestScreenCaptureAccess()) });
    }
    if (argc < 4 || (strcmp(argv[1], "capture") != 0 && strcmp(argv[1], "action") != 0 &&
        strcmp(argv[1], "inspect") != 0 && strcmp(argv[1], "type") != 0 &&
        strcmp(argv[1], "focus") != 0)) return fail(@"invalid_request");
    NSString *mode = strcmp(argv[1], "capture") == 0 ? [NSString stringWithUTF8String:argv[2]] : @"";
    NSString *bundleId = [NSString stringWithUTF8String:argv[3]];
    NSString *windowHint = argc > 4 ? [NSString stringWithUTF8String:argv[4]] : @"";
    if ((strcmp(argv[1], "capture") == 0 && ![@[@"screen", @"active_window", @"selected_window"] containsObject:mode]) ||
        ![@[@"com.google.Chrome", @"com.apple.Safari"] containsObject:bundleId] ||
        (windowHint.length > 0 && sensitiveTitle(windowHint))) return fail(@"target_denied");
    if (strcmp(argv[1], "capture") == 0 && !CGPreflightScreenCaptureAccess()) return fail(@"screen_recording_permission");
    NSRunningApplication *frontmost = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (strcmp(argv[1], "focus") == 0) {
      if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
      NSArray<NSRunningApplication *> *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleId];
      if (apps.count == 0) return fail(@"app_not_running");
      [apps[0] activateWithOptions:NSApplicationActivateIgnoringOtherApps];
      for (NSUInteger attempt = 0; attempt < 30; attempt++) {
        frontmost = NSWorkspace.sharedWorkspace.frontmostApplication;
        if ([frontmost.bundleIdentifier isEqualToString:bundleId]) break;
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
      }
    }
    if (![frontmost.bundleIdentifier isEqualToString:bundleId]) return fail(@"app_not_frontmost");
    NSArray<NSDictionary *> *windows = CFBridgingRelease(CGWindowListCopyWindowInfo(
      kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID));
    enableBrowserAccessibility(bundleId, frontmost.processIdentifier);
    if (strcmp(argv[1], "action") == 0) return performAction(bundleId, windowHint, windows, frontmost, argc, argv);
    NSUInteger selectedPosition = NSNotFound;
    NSDictionary *selected = browserWindow(windows, frontmost.processIdentifier, windowHint, &selectedPosition);
    if (selected == nil) return fail(@"window_not_found");
    NSString *title = selected[(id)kCGWindowName] ?: @"";
    if (sensitiveTitle(title)) return fail(@"target_denied");
    if (strcmp(argv[1], "focus") == 0) {
      return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
        @"window_index": @0, @"window_title": title, @"focused": @YES });
    }
    if (strcmp(argv[1], "inspect") == 0) {
      NSInteger maxNodes;
      if (argc != 6 || !parseNumber(argv[5], 1, 2000, &maxNodes)) return fail(@"invalid_request");
      return inspectUi(bundleId, title, frontmost.processIdentifier, maxNodes);
    }
    if (strcmp(argv[1], "type") == 0) {
      if (argc != 7 || windowHint.length == 0) return fail(@"invalid_request");
      return typeIntoFocused(bundleId, title, frontmost.processIdentifier, argv[5], argv[6]);
    }
    CGRect bounds = CGRectZero;
    CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)selected[(id)kCGWindowBounds], &bounds);
    if ([mode isEqualToString:@"screen"]) {
      CGRect displayBounds = CGDisplayBounds(CGMainDisplayID());
      if (!CGRectIntersectsRect(bounds, displayBounds)) return fail(@"target_denied");
      for (NSUInteger index = 0; index < windows.count; index++) {
        if (index == selectedPosition) continue;
        NSDictionary *window = windows[index];
        if ([window[(id)kCGWindowAlpha] doubleValue] < 0.01) continue;
        CGRect overlayBounds = CGRectZero;
        CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)window[(id)kCGWindowBounds], &overlayBounds);
        if (!CGRectIntersectsRect(overlayBounds, displayBounds)) continue;
        NSInteger layer = [window[(id)kCGWindowLayer] integerValue];
        NSString *ownerId = [NSRunningApplication runningApplicationWithProcessIdentifier:
          [window[(id)kCGWindowOwnerPID] intValue]].bundleIdentifier;
        if (isExcludedScreenOverlay(ownerId, layer)) continue;
        BOOL sensitive = sensitiveTitle(window[(id)kCGWindowName] ?: @"") ||
          [@[@"com.apple.SecurityAgent", @"com.apple.securityagent", @"com.apple.KeychainAccess",
             @"com.apple.systempreferences", @"com.apple.loginwindow"] containsObject:ownerId ?: @""];
        NSString *reason = screenWindowBlockReason(index < selectedPosition, layer, bounds, overlayBounds, sensitive);
        if (reason != nil) return fail(reason);
      }
    }
    CGImageRef image = captureImage(mode, [selected[(id)kCGWindowNumber] unsignedIntValue]);
    if (image == NULL) return fail(@"capture_failed");
    size_t imageWidth = CGImageGetWidth(image);
    size_t imageHeight = CGImageGetHeight(image);
    NSData *jpeg = jpegForImage(image, 1600);
    CGImageRelease(image);
    if (jpeg == nil) return fail(@"image_limit");
    CGDirectDisplayID display = CGMainDisplayID();
    return emit(@{
      @"status": @"ok", @"mode": mode,
      @"app_id": [@"bundle:" stringByAppendingString:bundleId],
      @"window_title": title,
      @"screen_width": @((NSInteger)CGDisplayBounds(display).size.width),
      @"screen_height": @((NSInteger)CGDisplayBounds(display).size.height),
      @"window_x": @(bounds.origin.x), @"window_y": @(bounds.origin.y),
      @"window_width": @(bounds.size.width), @"window_height": @(bounds.size.height),
      @"capture_width": @(imageWidth), @"capture_height": @(imageHeight),
      @"image_width": @(MAX(1, (size_t)floor(imageWidth * MIN(1.0, 1600.0 / (double)MAX(imageWidth, imageHeight))))),
      @"image_height": @(MAX(1, (size_t)floor(imageHeight * MIN(1.0, 1600.0 / (double)MAX(imageWidth, imageHeight))))),
      @"image_base64": [jpeg base64EncodedStringWithOptions:0]
    });
  }
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc == 3 && strcmp(argv[1], "--broker-socket") == 0) {
      [NSApplication sharedApplication];
      [NSApp finishLaunching];
      NSDictionary *request = receiveGuiRequest([NSString stringWithUTF8String:argv[2]]);
      if (request == nil) return 74;
      NSArray<NSString *> *arguments = request[@"args"];
      const char *values[34] = { argv[0] };
      for (NSUInteger index = 0; index < arguments.count; index++) values[index + 1] = arguments[index].UTF8String;
      int result = executeGui((int)arguments.count + 1, values);
      fflush(stdout);
      return result;
    }
    return executeGui(argc, argv);
  }
}
