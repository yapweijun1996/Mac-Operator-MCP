#pragma once

@interface GuiDesktopTarget : NSObject
@property CGDirectDisplayID display;
@property CGRect bounds;
@property NSString *layoutHash;
@property NSRunningApplication *frontmost;
@property NSString *identity;
@end
@implementation GuiDesktopTarget
@end

static NSSet<NSString *> *desktopDeniedApplications(const char *manifest) {
  if (manifest == NULL || strlen(manifest) == 0 || strlen(manifest) > 4096) return nil;
  NSData *data = [[NSString stringWithUTF8String:manifest] dataUsingEncoding:NSUTF8StringEncoding];
  id value = data == nil ? nil : [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  if (![value isKindOfClass:NSArray.class] || [value count] > 128) return nil;
  NSMutableSet *denied = [NSMutableSet set];
  for (id bundle in value) {
    if (![bundle isKindOfClass:NSString.class] || !isGuiBundleIdentifier(bundle)) return nil;
    [denied addObject:[bundle lowercaseString]];
  }
  return denied;
}

static BOOL desktopApplicationDenied(NSString *bundle, NSSet<NSString *> *denied) {
  return !isGuiBundleIdentifier(bundle) || isSensitiveApplicationBundle(bundle) ||
    [denied containsObject:bundle.lowercaseString];
}

static BOOL desktopSessionAllowed(NSString **reason) {
  CFDictionaryRef raw = CGSessionCopyCurrentDictionary();
  NSDictionary *session = CFBridgingRelease(raw);
  NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (session == nil || [session[@"CGSSessionScreenIsLocked"] boolValue] ||
      ![session[(__bridge id)kCGSessionOnConsoleKey] boolValue] ||
      front == nil || protectedGuiSession(front.bundleIdentifier)) {
    *reason = @"protected_session"; return NO;
  }
  return YES;
}

static NSString *desktopLayout(CGDirectDisplayID selected, CGRect *selectedBounds) {
  CGDirectDisplayID displays[64]; uint32_t count = 0;
  if (CGGetActiveDisplayList(64, displays, &count) != kCGErrorSuccess || count == 0 || count > 64) return nil;
  NSMutableArray<NSNumber *> *ids = [NSMutableArray array];
  for (uint32_t index = 0; index < count; index++) [ids addObject:@(displays[index])];
  [ids sortUsingSelector:@selector(compare:)];
  NSMutableString *layout = [NSMutableString stringWithFormat:@"main:%u;", CGMainDisplayID()];
  BOOL found = NO;
  for (NSNumber *identifier in ids) {
    CGRect bounds = CGDisplayBounds(identifier.unsignedIntValue);
    CGFloat values[] = {bounds.origin.x, bounds.origin.y, bounds.size.width, bounds.size.height};
    for (NSUInteger index = 0; index < 4; index++) {
      if (!isfinite(values[index]) || fabs(values[index]) > 20000 || floor(values[index]) != values[index]) return nil;
    }
    if (bounds.size.width <= 0 || bounds.size.height <= 0) return nil;
    [layout appendFormat:@"%u:%.0f,%.0f,%.0f,%.0f;", identifier.unsignedIntValue,
      bounds.origin.x, bounds.origin.y, bounds.size.width, bounds.size.height];
    if (identifier.unsignedIntValue == selected) { found = YES; *selectedBounds = bounds; }
  }
  if (!found) return nil;
  NSData *data = [layout dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *hash = [NSMutableString stringWithCapacity:64];
  for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) [hash appendFormat:@"%02x", digest[index]];
  return hash;
}

static GuiDesktopTarget *resolveGuiDesktop(NSString *hint, NSString *expected, NSSet<NSString *> *denied,
                                           BOOL requireForeground, NSString **reason) {
  if (!desktopSessionAllowed(reason)) return nil;
  CGDirectDisplayID display = CGMainDisplayID();
  if (hint.length > 0) {
    NSInteger parsed;
    if (![hint hasPrefix:@"display:"] || !parseNumber([hint substringFromIndex:8].UTF8String, 1, UINT32_MAX, &parsed)) {
      *reason = @"invalid_request"; return nil;
    }
    display = (CGDirectDisplayID)parsed;
  } else if (expected.length > 0) {
    NSArray *parts = [expected componentsSeparatedByString:@":"]; NSInteger parsed;
    if (parts.count != 5 || ![parts[0] isEqualToString:@"desktop"] ||
        !parseNumber([parts[1] UTF8String], 1, UINT32_MAX, &parsed)) { *reason = @"stale_target"; return nil; }
    display = (CGDirectDisplayID)parsed;
  }
  CGRect bounds = CGRectZero; NSString *hash = desktopLayout(display, &bounds);
  if (hash == nil) { *reason = @"stale_target"; return nil; }
  NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
  if (front.processIdentifier <= 0 || front.terminated || front.launchDate == nil ||
      desktopApplicationDenied(front.bundleIdentifier, denied)) { *reason = @"target_denied"; return nil; }
  NSString *identity = [NSString stringWithFormat:@"desktop:%u:%@:%d:%lld", display, hash,
    front.processIdentifier, (long long)(front.launchDate.timeIntervalSince1970 * 1000)];
  if (expected.length > 0) {
    NSArray<NSString *> *parts = [expected componentsSeparatedByString:@":"]; NSInteger pid=0, launched=0;
    if (parts.count != 5 || ![parts[0] isEqualToString:@"desktop"] ||
        ![parts[1] isEqualToString:[NSString stringWithFormat:@"%u", display]] || ![parts[2] isEqualToString:hash] ||
        !parseNumber(parts[3].UTF8String,1,INT_MAX,&pid) || !parseNumber(parts[4].UTF8String,1,LONG_MAX,&launched) ||
        ![parts[3] isEqualToString:[NSString stringWithFormat:@"%ld",(long)pid]] ||
        ![parts[4] isEqualToString:[NSString stringWithFormat:@"%ld",(long)launched]] ||
        (requireForeground && ![expected isEqualToString:identity])) { *reason = @"stale_target"; return nil; }
  }
  GuiDesktopTarget *target = [GuiDesktopTarget new]; target.display = display; target.bounds = bounds;
  target.layoutHash = hash; target.frontmost = front; target.identity = expected.length > 0 ? expected : identity;
  return target;
}

static BOOL desktopVisibleWindowsAllowed(GuiDesktopTarget *target, NSSet<NSString *> *denied, NSString **reason) {
  NSArray *windows = CFBridgingRelease(CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID));
  if (windows == nil || windows.count > 4096) { *reason = @"ax_enumeration_failed"; return NO; }
  for (NSDictionary *window in windows) {
    if (![window isKindOfClass:NSDictionary.class]) { *reason = @"ax_enumeration_failed"; return NO; }
    if ([window[(id)kCGWindowAlpha] doubleValue] < 0.01 ||
        (window[(id)kCGWindowIsOnscreen] != nil && ![window[(id)kCGWindowIsOnscreen] boolValue])) continue;
    CGRect bounds = CGRectZero;
    if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)window[(id)kCGWindowBounds], &bounds)) {
      *reason = @"ax_enumeration_failed"; return NO;
    }
    if (!CGRectIntersectsRect(bounds, target.bounds)) continue;
    NSString *bundle = [NSRunningApplication runningApplicationWithProcessIdentifier:
      [window[(id)kCGWindowOwnerPID] intValue]].bundleIdentifier;
    NSString *title = window[(id)kCGWindowName];
    if ((title != nil && (![title isKindOfClass:NSString.class] || sensitiveTitle(title))) ||
        (bundle != nil && desktopApplicationDenied(bundle, denied)) ||
        (bundle == nil && [window[(id)kCGWindowLayer] intValue] == 0)) {
      *reason = @"sensitive_window_visible"; return NO;
    }
  }
  return YES;
}

static BOOL desktopElementAllowed(AXUIElementRef element, NSSet<NSString *> *denied, NSString **reason) {
  pid_t pid = -1;
  if (element == NULL || AXUIElementGetPid(element, &pid) != kAXErrorSuccess || pid <= 0) {
    *reason = @"secure_target"; return NO;
  }
  NSRunningApplication *app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
  if (app == nil || app.terminated || desktopApplicationDenied(app.bundleIdentifier, denied)) {
    *reason = @"target_denied"; return NO;
  }
  AXUIElementRef cursor = (AXUIElementRef)CFRetain(element);
  BOOL allowed = YES;
  for (NSUInteger depth = 0; depth < 16; depth++) {
    NSString *role = attributeText(cursor, kAXRoleAttribute), *label = elementLabel(cursor);
    if (role.length == 0 || role.length > 128 || secureElement(cursor) || sensitiveAction(label) ||
        [@[@"Passwords", @"Keychain Access", @"System Settings", @"System Preferences"] containsObject:label]) {
      *reason = @"secure_target"; allowed = NO; break;
    }
    // Dock application icons can name an app distinct from their own Dock PID.
    CFTypeRef rawUrl = NULL;
    if (AXUIElementCopyAttributeValue(cursor, kAXURLAttribute, &rawUrl) == kAXErrorSuccess && rawUrl != NULL) {
      NSURL *url = CFGetTypeID(rawUrl) == CFURLGetTypeID() ? (__bridge NSURL *)rawUrl : nil;
      if (url != nil && url.isFileURL && [url.path.pathExtension.lowercaseString isEqualToString:@"app"] &&
          desktopApplicationDenied([NSBundle bundleWithURL:url].bundleIdentifier, denied)) {
        *reason = @"target_denied"; allowed = NO;
      }
      CFRelease(rawUrl); if (!allowed) break;
    }
    if ([role isEqualToString:@"AXApplication"] || [role isEqualToString:@"AXSystemWide"]) break;
    CFTypeRef parent = NULL;
    AXError error = AXUIElementCopyAttributeValue(cursor, kAXParentAttribute, &parent);
    if (error != kAXErrorSuccess || parent == NULL) {
      if (parent != NULL) CFRelease(parent); *reason = @"secure_target"; allowed = NO; break;
    }
    if (CFGetTypeID(parent) != AXUIElementGetTypeID()) { CFRelease(parent); *reason = @"secure_target"; allowed = NO; break; }
    CFRelease(cursor); cursor = (AXUIElementRef)parent;
    if (depth == 15) { *reason = @"secure_target"; allowed = NO; }
  }
  CFRelease(cursor); return allowed;
}

static BOOL desktopPointerAllowed(GuiDesktopTarget *target, CGPoint point, NSSet<NSString *> *denied, NSString **reason) {
  if (!CGRectContainsPoint(target.bounds, point) || !isDesktopPoint(point)) { *reason = @"outside_window"; return NO; }
  AXUIElementRef system = AXUIElementCreateSystemWide(), hit = NULL;
  AXUIElementSetMessagingTimeout(system, 0.5);
  AXError error = AXUIElementCopyElementAtPosition(system, point.x, point.y, &hit); CFRelease(system);
  BOOL allowed = error == kAXErrorSuccess && hit != NULL && desktopElementAllowed(hit, denied, reason);
  if (hit != NULL) CFRelease(hit);
  if (error != kAXErrorSuccess || hit == NULL) *reason = error == kAXErrorAPIDisabled ? @"accessibility_permission" : @"secure_target";
  return allowed;
}

static AXUIElementRef desktopFocusedElement(GuiDesktopTarget *target, NSSet<NSString *> *denied, BOOL typing, NSString **reason) {
  if (!readGuiFrontmost(target.frontmost, reason)) return NULL;
  AXUIElementRef element = focusedElement(target.frontmost.processIdentifier); pid_t pid = -1;
  if (element == NULL || AXUIElementGetPid(element, &pid) != kAXErrorSuccess ||
      pid != target.frontmost.processIdentifier || !desktopElementAllowed(element, denied, reason) ||
      (typing && (!textRole(attributeText(element, kAXRoleAttribute)) || !attributeBool(element, kAXEnabledAttribute, NO)))) {
    if (element != NULL) CFRelease(element); *reason = @"secure_target"; return NULL;
  }
  return element;
}

static BOOL desktopRevalidate(GuiDesktopTarget *target, NSSet<NSString *> *denied, BOOL foreground, NSString **reason) {
  GuiDesktopTarget *current = resolveGuiDesktop(@"", target.identity, denied, foreground, reason);
  return current != nil && desktopVisibleWindowsAllowed(current, denied, reason);
}

static BOOL desktopKeyboardReady(GuiDesktopTarget *target, NSSet<NSString *> *denied,
                                 AXUIElementRef expectedFocus, BOOL typing, NSString **reason) {
  if (!desktopRevalidate(target, denied, YES, reason)) return NO;
  AXUIElementRef focused = desktopFocusedElement(target, denied, typing, reason);
  BOOL ready = focused != NULL && (expectedFocus == NULL || CFEqual(focused, expectedFocus));
  if (focused != NULL) CFRelease(focused);
  if (!ready && *reason == nil) *reason = @"focus_changed";
  return ready;
}

static CGImageRef captureDesktopImage(CGDirectDisplayID selected, NSSet<NSString *> *denied) {
  dispatch_semaphore_t ready = dispatch_semaphore_create(0); __block SCShareableContent *content = nil;
  [SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:YES
    completionHandler:^(SCShareableContent *value, NSError *error) { if (error == nil) content = value; dispatch_semaphore_signal(ready); }];
  if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0 || content == nil ||
      content.applications.count > 4096 || content.windows.count > 4096) return NULL;
  NSMutableArray<SCRunningApplication *> *excluded = [NSMutableArray array]; NSMutableSet *excludedPids = [NSMutableSet set];
  NSMutableSet *knownPids = [NSMutableSet set];
  for (SCRunningApplication *app in content.applications) {
    NSRunningApplication *live = [NSRunningApplication runningApplicationWithProcessIdentifier:app.processID];
    if (app.processID <= 0 || live == nil || live.terminated || live.processIdentifier != app.processID ||
        ![live.bundleIdentifier isEqualToString:app.bundleIdentifier] || desktopApplicationDenied(app.bundleIdentifier, denied)) {
      [excluded addObject:app]; [excludedPids addObject:@(app.processID)];
    } else [knownPids addObject:@(app.processID)];
  }
  NSMutableArray<SCWindow *> *excepted = [NSMutableArray array];
  for (SCWindow *window in content.windows) {
    // With an exclusion filter, excepting a denied app's window would include its pixels.
    pid_t owner = window.owningApplication.processID;
    if (![excludedPids containsObject:@(owner)] &&
        (window.owningApplication == nil || ![knownPids containsObject:@(owner)] || sensitiveTitle(window.title ?: @""))) [excepted addObject:window];
  }
  SCContentFilter *filter = nil;
  for (SCDisplay *display in content.displays) if (display.displayID == selected) {
    // Exclusion preserves Dock and wallpaper. Pre/post scans also reject current protected surfaces;
    // a new transient process after this catalog remains an explicit capture-race limitation.
    filter = [[SCContentFilter alloc] initWithDisplay:display excludingApplications:excluded exceptingWindows:excepted];
    if (@available(macOS 14.2, *)) filter.includeMenuBar = YES;
    break;
  }
  if (filter == nil) return NULL;
  SCStreamConfiguration *configuration = [SCStreamConfiguration new];
  configuration.width = MAX(1, (size_t)ceil(filter.contentRect.size.width * filter.pointPixelScale));
  configuration.height = MAX(1, (size_t)ceil(filter.contentRect.size.height * filter.pointPixelScale)); configuration.showsCursor = NO;
  dispatch_semaphore_t captured = dispatch_semaphore_create(0); __block CGImageRef image = NULL;
  [SCScreenshotManager captureImageWithFilter:filter configuration:configuration completionHandler:^(CGImageRef value, NSError *error) {
    if (error == nil && value != NULL) image = CGImageRetain(value); dispatch_semaphore_signal(captured);
  }];
  if (dispatch_semaphore_wait(captured, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) return NULL;
  return image;
}

static int captureGuiDesktop(GuiDesktopTarget *target, NSSet<NSString *> *denied) {
  if (!CGPreflightScreenCaptureAccess()) return fail(@"screen_recording_permission");
  CGImageRef image = captureDesktopImage(target.display, denied);
  if (image == NULL) return fail(@"capture_failed");
  NSString *reason = nil;
  if (!desktopRevalidate(target, denied, YES, &reason)) { CGImageRelease(image); return fail(reason); }
  size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image); NSData *jpeg = jpegForImage(image, 1600); CGImageRelease(image);
  if (jpeg == nil) return fail(@"image_limit");
  double scale = MIN(1.0, 1600.0 / (double)MAX(width, height));
  return emit(@{ @"status":@"ok", @"mode":@"screen", @"app_id":@"bundle:dev.macoperator.desktop",
    @"window_title":@"Desktop", @"window_identity":target.identity,
    @"screen_width":@(target.bounds.size.width), @"screen_height":@(target.bounds.size.height),
    @"window_x":@(target.bounds.origin.x), @"window_y":@(target.bounds.origin.y),
    @"window_width":@(target.bounds.size.width), @"window_height":@(target.bounds.size.height),
    @"capture_width":@(width), @"capture_height":@(height), @"image_width":@(MAX(1,(size_t)floor(width*scale))),
    @"image_height":@(MAX(1,(size_t)floor(height*scale))), @"image_base64":[jpeg base64EncodedStringWithOptions:0] });
}

static int actionGuiDesktop(GuiDesktopTarget *target, NSSet<NSString *> *denied, const char *argv[]) {
  NSString *action = [NSString stringWithUTF8String:argv[5]], *key = [NSString stringWithUTF8String:argv[10]];
  NSInteger x,y,dx,dy,wait;
  if (!parseNumber(argv[6],-20000,20000,&x) || !parseNumber(argv[7],-20000,20000,&y) ||
      !parseNumber(argv[8],-1000,1000,&dx) || !parseNumber(argv[9],-1000,1000,&dy) ||
      !parseNumber(argv[11],0,2000,&wait)) return fail(@"invalid_request");
  BOOL pointer = [@[@"click",@"double_click",@"right_click",@"move_pointer",@"scroll"] containsObject:action];
  BOOL keyboard = [@[@"key_press",@"shortcut"] containsObject:action]; NSString *reason = nil; CGPoint point=CGPointMake(x,y);
  if (!pointer && !keyboard && ![action isEqualToString:@"wait"]) return fail(@"invalid_request");
  if (!desktopRevalidate(target,denied,keyboard,&reason)) return fail(reason);
  if (pointer && !desktopPointerAllowed(target,point,denied,&reason)) return fail(reason);
  if (keyboard) {
    AXUIElementRef focused = desktopFocusedElement(target,denied,NO,&reason); if (focused == NULL) return fail(reason); CFRelease(focused);
    NSDictionary *codes=@{@"ENTER":@36,@"TAB":@48,@"ESCAPE":@53,@"BACKSPACE":@51,@"ARROW_UP":@126,@"ARROW_DOWN":@125,
      @"ARROW_LEFT":@123,@"ARROW_RIGHT":@124,@"HOME":@115,@"END":@119,@"PAGE_UP":@116,@"PAGE_DOWN":@121,@"SPACE":@49,
      @"COMMAND_L":@37,@"COMMAND_R":@15,@"COMMAND_F":@3};
    BOOL shortcut=[action isEqualToString:@"shortcut"];
    if (codes[key]==nil || shortcut != [key hasPrefix:@"COMMAND_"]) return fail(@"invalid_request");
    if (!desktopKeyboardReady(target,denied,NULL,NO,&reason)) return fail(reason);
    if (!postKey([codes[key] unsignedShortValue],shortcut?kCGEventFlagMaskCommand:0)) return fail(@"execution_failed");
  } else if ([action isEqualToString:@"wait"]) usleep((useconds_t)wait*1000);
  else if ([action isEqualToString:@"scroll"]) {
    CGEventRef event=CGEventCreateScrollWheelEvent(NULL,kCGScrollEventUnitPixel,2,(int32_t)dy,(int32_t)dx);
    if (event==NULL) return fail(@"execution_failed"); CGEventSetLocation(event,point); CGEventPost(kCGHIDEventTap,event); CFRelease(event);
  } else if ([action isEqualToString:@"move_pointer"]) {
    CGEventRef event=CGEventCreateMouseEvent(NULL,kCGEventMouseMoved,point,kCGMouseButtonLeft);
    if (event==NULL) return fail(@"execution_failed"); CGEventPost(kCGHIDEventTap,event); CFRelease(event);
  } else {
    BOOL right=[action isEqualToString:@"right_click"]; NSInteger count=[action isEqualToString:@"double_click"]?2:1;
    for (NSInteger index=1;index<=count;index++) {
      if (!desktopRevalidate(target,denied,NO,&reason) || !desktopPointerAllowed(target,point,denied,&reason)) return fail(reason);
      for (NSNumber *down in @[@YES,@NO]) {
        CGEventType kind=right?(down.boolValue?kCGEventRightMouseDown:kCGEventRightMouseUp):(down.boolValue?kCGEventLeftMouseDown:kCGEventLeftMouseUp);
        CGEventRef event=CGEventCreateMouseEvent(NULL,kind,point,right?kCGMouseButtonRight:kCGMouseButtonLeft);
        if (event==NULL) return fail(@"execution_failed"); CGEventSetIntegerValueField(event,kCGMouseEventClickState,index);
        CGEventPost(kCGHIDEventTap,event); CFRelease(event);
      }
    }
  }
  if (![action isEqualToString:@"wait"]) usleep(250000);
  if (!desktopRevalidate(target,denied,keyboard,&reason)) return fail(reason);
  return emit(@{@"status":@"ok",@"app_id":@"bundle:dev.macoperator.desktop",@"window_title":@"Desktop",@"window_identity":target.identity,
    @"action":action,@"accepted":@YES,@"focused":@YES});
}

static int typeGuiDesktop(GuiDesktopTarget *target, NSSet<NSString *> *denied, const char *argv[]) {
  NSString *reason=nil; AXUIElementRef focused=desktopFocusedElement(target,denied,YES,&reason);
  if (focused==NULL) return fail(reason);
  id stableFocus=CFBridgingRelease(focused);
  NSMutableData *input=[NSMutableData data]; uint8_t buffer[4096];
  while (!feof(stdin) && input.length<=40000) { size_t count=fread(buffer,1,sizeof(buffer),stdin); if (count==0) break; [input appendBytes:buffer length:count]; }
  if (input.length>40000 || ferror(stdin)) return fail(@"invalid_request");
  id request=[NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
  if (![request isKindOfClass:NSDictionary.class] || ![request[@"text"] isKindOfClass:NSString.class] ||
      ![request[@"keys"] isKindOfClass:NSArray.class] || ![request[@"submit"] isKindOfClass:NSNumber.class] ||
      CFGetTypeID((__bridge CFTypeRef)request[@"submit"])!=CFBooleanGetTypeID() ||
      (request[@"navigation"]!=nil && (![request[@"navigation"] isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)request[@"navigation"])!=CFBooleanGetTypeID() || [request[@"navigation"] boolValue]))) return fail(@"invalid_request");
  NSString *text=request[@"text"]; NSArray *keys=request[@"keys"]; if (text.length>10000 || keys.count>32) return fail(@"invalid_request");
  NSDictionary *codes=@{@"ENTER":@36,@"TAB":@48,@"ESCAPE":@53,@"ARROW_UP":@126,@"ARROW_DOWN":@125,@"ARROW_LEFT":@123,@"ARROW_RIGHT":@124,@"HOME":@115,@"END":@119};
  for (id key in keys) if (![key isKindOfClass:NSString.class] || codes[key]==nil) return fail(@"invalid_request");
  for (NSUInteger index=0;index<text.length;index++) if ([text characterAtIndex:index]==0) return fail(@"invalid_request");
  for (NSUInteger offset=0;offset<text.length;) {
    if (!desktopKeyboardReady(target,denied,(__bridge AXUIElementRef)stableFocus,YES,&reason)) return fail(reason);
    NSUInteger length=1;
    if (CFStringIsSurrogateHighCharacter([text characterAtIndex:offset]) && offset+1<text.length && CFStringIsSurrogateLowCharacter([text characterAtIndex:offset+1])) length=2;
    UniChar characters[2]; [text getCharacters:characters range:NSMakeRange(offset,length)]; offset+=length;
    for (NSNumber *down in @[@YES,@NO]) {
      CGEventRef event=CGEventCreateKeyboardEvent(NULL,0,down.boolValue); if (event==NULL) return fail(@"execution_failed");
      CGEventSetFlags(event,0); CGEventKeyboardSetUnicodeString(event,length,characters); CGEventPost(kCGHIDEventTap,event); CFRelease(event);
    }
  }
  for (NSString *key in keys) {
    if (!desktopKeyboardReady(target,denied,NULL,NO,&reason)) return fail(reason);
    if (!postKey([codes[key] unsignedShortValue],0)) return fail(@"execution_failed");
  }
  if ([request[@"submit"] boolValue]) {
    if (!desktopKeyboardReady(target,denied,NULL,NO,&reason)) return fail(reason);
    if (!postKey(36,0)) return fail(@"execution_failed");
  }
  usleep(250000);
  if (!desktopKeyboardReady(target,denied,NULL,NO,&reason)) return fail(reason);
  return emit(@{@"status":@"ok",@"app_id":@"bundle:dev.macoperator.desktop",@"window_index":@0,@"window_title":@"Desktop",
    @"window_identity":target.identity,@"element_index":@-1,@"role":[NSString stringWithUTF8String:argv[5]],
    @"characters_accepted":@(text.length),@"keys_accepted":keys,@"submitted":request[@"submit"],@"focus_confirmed":@YES,@"secure":@NO});
}

static int executeGuiDesktop(int argc, const char *argv[]) {
  BOOL inspect=strcmp(argv[1],"inspect")==0,capture=strcmp(argv[1],"capture")==0;
  BOOL action=strcmp(argv[1],"action")==0,type=strcmp(argv[1],"type")==0;
  if ((inspect && argc!=7 && argc!=8) || (capture && (argc!=7 || strcmp(argv[2],"screen")!=0)) ||
      (action && argc!=14) || (type && (argc!=9 || strcmp(argv[5],"VisualWindow")!=0)) || (!inspect && !capture && !action && !type)) return fail(@"invalid_request");
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  NSSet *denied=desktopDeniedApplications(argv[argc-1]); if (denied==nil) return fail(@"invalid_request");
  NSString *expected=inspect && argc==7 ? @"" : [NSString stringWithUTF8String:argv[argc-2]];
  NSString *reason=nil; BOOL keyboard=type || (action && (strcmp(argv[5],"key_press")==0 || strcmp(argv[5],"shortcut")==0));
  if (!inspect && expected.length==0) return fail(@"invalid_request");
  GuiDesktopTarget *target=resolveGuiDesktop([NSString stringWithUTF8String:argv[4]],expected,denied,capture||keyboard,&reason);
  if (target==nil || !desktopVisibleWindowsAllowed(target,denied,&reason)) return fail(reason);
  if (capture) return captureGuiDesktop(target,denied);
  if (action) return actionGuiDesktop(target,denied,argv);
  if (type) return typeGuiDesktop(target,denied,argv);
  NSInteger maxNodes; if (!parseNumber(argv[5],1,2000,&maxNodes)) return fail(@"invalid_request");
  return emit(@{@"status":@"ok",@"app_id":@"bundle:dev.macoperator.desktop",@"window_index":@0,@"window_title":@"Desktop",
    @"window_identity":target.identity,@"focused":@YES,@"nodes":@[],@"truncated":@NO});
}
