#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <CommonCrypto/CommonDigest.h>
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

static BOOL isBrowserApplication(NSString *bundleId) {
  return [@[@"com.google.Chrome", @"com.apple.Safari"] containsObject:bundleId];
}

static BOOL isSensitiveApplicationBundle(NSString *bundleId) {
  return [@[@"com.apple.securityagent", @"com.apple.keychainaccess", @"com.apple.passwords",
             @"com.apple.systempreferences", @"com.apple.loginwindow"] containsObject:bundleId.lowercaseString ?: @""];
}

static BOOL isGuiBundleIdentifier(NSString *bundleId) {
  if (bundleId == nil || bundleId.length == 0 || bundleId.length > 256) return NO;
  NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
    @"^[A-Za-z0-9][A-Za-z0-9._:@+\\-]{0,255}$" options:0 error:nil];
  NSTextCheckingResult *match = [pattern firstMatchInString:bundleId options:0 range:NSMakeRange(0, bundleId.length)];
  if (match == nil || match.range.location != 0 || match.range.length != bundleId.length) return NO;
  return YES;
}

static BOOL isGuiApplicationBundle(NSString *bundleId) {
  return isGuiBundleIdentifier(bundleId) && !isSensitiveApplicationBundle(bundleId);
}

static BOOL sensitiveTitle(NSString *title) {
  NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
    @"(?i)\\b(passwords?|passcodes?|credentials?|security|privacy|private key|sign in|log in|two.factor|verification code)\\b"
    options:0 error:nil];
  return [pattern firstMatchInString:title options:0 range:NSMakeRange(0, title.length)] != nil;
}

static BOOL sensitiveAction(NSString *label) {
  NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
    @"(?i)\\b(buy|purchase|pay|checkout|send|publish|delete|remove|erase|security|privacy)\\b"
    options:0 error:nil];
  return [pattern firstMatchInString:label options:0 range:NSMakeRange(0, label.length)] != nil;
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

static BOOL browserNavigationAncestors(NSArray<NSString *> *roles) {
  BOOL toolbar = NO;
  for (NSString *role in roles) {
    if ([role isEqualToString:@"AXWebArea"]) return NO;
    if ([role isEqualToString:@"AXToolbar"]) toolbar = YES;
    if ([role isEqualToString:@"AXWindow"]) return toolbar;
  }
  return NO;
}

static BOOL browserNavigationElement(AXUIElementRef element, NSString *bundleId) {
  if (!isBrowserApplication(bundleId)) return NO;
  if (!textRole(attributeText(element, kAXRoleAttribute))) return NO;
  NSString *label = elementLabel(element);
  NSRegularExpression *pattern = [NSRegularExpression regularExpressionWithPattern:
    @"(?i)\\b(address|location|omnibox|smart search field)\\b" options:0 error:nil];
  if ([pattern firstMatchInString:label options:0 range:NSMakeRange(0, label.length)] == nil) return NO;
  AXUIElementRef cursor = (AXUIElementRef)CFRetain(element);
  NSMutableArray<NSString *> *roles = [NSMutableArray array];
  for (NSUInteger depth = 0; depth < 16; depth++) {
    NSString *role = attributeText(cursor, kAXRoleAttribute);
    [roles addObject:role];
    if ([role isEqualToString:@"AXWebArea"] || [role isEqualToString:@"AXWindow"]) break;
    CFTypeRef parent = NULL;
    AXUIElementCopyAttributeValue(cursor, kAXParentAttribute, &parent);
    if (parent == NULL || CFGetTypeID(parent) != AXUIElementGetTypeID()) {
      if (parent != NULL) CFRelease(parent);
      break;
    }
    CFRelease(cursor); cursor = (AXUIElementRef)parent;
  }
  CFRelease(cursor);
  return browserNavigationAncestors(roles);
}

static BOOL boundedNavigationInput(NSString *text, NSArray *keys, BOOL submit) {
  NSURLComponents *url = [NSURLComponents componentsWithString:text];
  return ((submit && keys.count == 0) || (!submit && keys.count == 1 && [keys[0] isEqualToString:@"ENTER"])) &&
    [url.scheme.lowercaseString isEqualToString:@"https"] && url.host.length > 0 &&
    url.user.length == 0 && url.password.length == 0 && url.fragment.length == 0;
}

static BOOL navigationDispatchAllowed(BOOL delegated, BOOL nativeToolbar, NSString *text, NSArray *keys, BOOL submit) {
  return !delegated || (nativeToolbar && boundedNavigationInput(text, keys, submit));
}

static BOOL navigationAddressMatches(NSString *requested, NSString *actual) {
  if (actual.length == 0 || actual.length > 10000) return NO;
  // Chrome may omit the HTTPS scheme in its toolbar presentation value.
  NSURLComponents *expected = [NSURLComponents componentsWithString:requested];
  NSURLComponents *observed = [NSURLComponents componentsWithString:
    [actual containsString:@"://"] ? actual : [@"https://" stringByAppendingString:actual]];
  NSString *expectedPath = expected.percentEncodedPath.length == 0 ? @"/" : expected.percentEncodedPath;
  NSString *observedPath = observed.percentEncodedPath.length == 0 ? @"/" : observed.percentEncodedPath;
  return [observed.scheme.lowercaseString isEqualToString:@"https"] && observed.user.length == 0 &&
    observed.password.length == 0 && observed.fragment.length == 0 &&
    [expected.host.lowercaseString isEqualToString:observed.host.lowercaseString] &&
    ((expected.port == nil && observed.port == nil) || [expected.port isEqual:observed.port]) &&
    [expectedPath isEqualToString:observedPath] &&
    ((expected.percentEncodedQuery == nil && observed.percentEncodedQuery == nil) ||
      [expected.percentEncodedQuery isEqualToString:observed.percentEncodedQuery]);
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

static BOOL isDesktopPoint(CGPoint point) {
  CGDirectDisplayID displays[64]; uint32_t count = 0;
  if (CGGetActiveDisplayList(64, displays, &count) != kCGErrorSuccess || count == 0) return NO;
  for (uint32_t index = 0; index < count; index++) {
    if (CGRectContainsPoint(CGDisplayBounds(displays[index]), point)) return YES;
  }
  return NO;
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

static BOOL secureElement(AXUIElementRef element) {
  return [attributeText(element, kAXSubroleAttribute) localizedCaseInsensitiveContainsString:@"secure"] ||
    [attributeText(element, kAXRoleAttribute) localizedCaseInsensitiveContainsString:@"secure"] ||
    sensitiveTitle(elementLabel(element));
}

static BOOL elementEnabled(AXUIElementRef element) {
  CFTypeRef value = NULL;
  AXError error = AXUIElementCopyAttributeValue(element, kAXEnabledAttribute, &value);
  BOOL enabled = error == kAXErrorSuccess && value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
    CFBooleanGetValue((CFBooleanRef)value);
  if (value != NULL) CFRelease(value);
  if (error != kAXErrorAttributeUnsupported) return enabled;
  // AppKit text views may omit AXEnabled while explicitly exposing editable
  // AXValue. A capability query never reads document text and cannot override
  // an explicit disabled flag, unreadable attribute, or protected field.
  if (!textRole(attributeText(element, kAXRoleAttribute)) || secureElement(element)) return NO;
  Boolean settable = false;
  return AXUIElementIsAttributeSettable(element, kAXValueAttribute, &settable) == kAXErrorSuccess && settable;
}

#import "gui_window.h"

static NSString *approvedElementAncestryBlockReason(GuiWindowTarget *target, AXUIElementRef element) {
  if (element == NULL) return @"secure_target";
  AXUIElementRef cursor = (AXUIElementRef)CFRetain(element);
  NSMutableArray *seen = [NSMutableArray array];
  NSString *blocked = @"secure_target";
  NSRegularExpression *authentication = [NSRegularExpression regularExpressionWithPattern:
    @"(?i)\\b(authentication|authorization|authenticate|authorize)\\b" options:0 error:nil];
  for (NSUInteger depth = 0; depth < 64; depth++) {
    if ([seen containsObject:(__bridge id)cursor]) break;
    [seen addObject:(__bridge id)cursor];
    pid_t pid = -1;
    if (AXUIElementGetPid(cursor, &pid) != kAXErrorSuccess || pid != target.application.processIdentifier) {
      blocked = @"stale_target"; break;
    }
    NSString *role = attributeText(cursor, kAXRoleAttribute), *label = elementLabel(cursor);
    if (role.length == 0 || role.length > 128 || secureElement(cursor) ||
        [authentication firstMatchInString:label options:0 range:NSMakeRange(0, label.length)] != nil) break;
    if (CFEqual(cursor, (__bridge CFTypeRef)target.axWindow)) { blocked = nil; break; }
    if ([role isEqualToString:@"AXWindow"]) { blocked = @"stale_target"; break; }
    if ([@[@"AXApplication", @"AXSystemWide"] containsObject:role]) break;
    CFTypeRef parent = NULL;
    AXError error = AXUIElementCopyAttributeValue(cursor, kAXParentAttribute, &parent);
    if (error != kAXErrorSuccess || parent == NULL || CFGetTypeID(parent) != AXUIElementGetTypeID()) {
      if (parent != NULL) CFRelease(parent); break;
    }
    CFRelease(cursor); cursor = (AXUIElementRef)parent;
  }
  CFRelease(cursor);
  return blocked;
}

// Tree order must not depend on focus or the observation limit: a toolbar action
// may change focus without changing any of the observed targets. Unexposed or
// truncated elements require another observation rather than a focus-based slot.
static NSArray *windowElements(pid_t pid, id selected, NSInteger limit, BOOL *truncated) {
  (void)pid;
  NSMutableArray *queue = [NSMutableArray arrayWithObject:selected];
  NSMutableArray *elements = [NSMutableArray array];
  for (NSUInteger cursor = 0; cursor < queue.count; cursor++) {
    id element = queue[cursor];
    if (elements.count >= (NSUInteger)limit) { *truncated = YES; break; }
    if (![elements containsObject:element]) [elements addObject:element];
    AXUIElementRef ax = (__bridge AXUIElementRef)element;
    // Never traverse inside a protected field or read its value.
    if (secureElement(ax)) continue;
    CFIndex count = 0;
    if (AXUIElementGetAttributeValueCount(ax, kAXChildrenAttribute, &count) != kAXErrorSuccess || count <= 0) continue;
    // Use the same hard queue bound for observe and dispatch. A smaller output
    // limit must not change breadth-first order when providers repeat children.
    CFIndex available = MAX(0, 2000 - (NSInteger)queue.count);
    if (count > available) *truncated = YES;
    CFArrayRef children = NULL;
    if (available > 0 && AXUIElementCopyAttributeValues(ax, kAXChildrenAttribute, 0, MIN(count, available), &children) == kAXErrorSuccess && children != NULL) {
      for (id child in (__bridge NSArray *)children) if (![queue containsObject:child]) [queue addObject:child];
    }
    if (children != NULL) CFRelease(children);
  }
  return elements;
}

static NSDictionary *guiNode(NSUInteger index, NSString *role, NSString *label, BOOL enabled,
                             BOOL focused, BOOL secure, BOOL navigation) {
  return @{ @"index": @(index), @"role": role, @"label": secure ? @"" : label,
    @"enabled": @(enabled), @"focused": @(focused), @"secure": @(secure),
    @"browser_navigation": @((BOOL)(navigation && !secure)) };
}

static int inspectUi(GuiWindowTarget *target, NSInteger maxNodes) {
  NSString *bundleId = target.application.bundleIdentifier, *title = target.title;
  pid_t pid = target.application.processIdentifier;
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  BOOL truncated = NO;
  NSArray *elements = windowElements(pid, target.axWindow, maxNodes, &truncated);
  if (elements == nil) return fail(@"window_not_found");
  NSMutableArray *nodes = [NSMutableArray array];
  AXUIElementRef focused = focusedElement(pid);
  for (id item in elements) {
    AXUIElementRef element = (__bridge AXUIElementRef)item;
    BOOL secure = secureElement(element);
    NSString *role = attributeText(element, kAXRoleAttribute);
    if (role.length == 0 || role.length > 128) { if (focused != NULL) CFRelease(focused); return fail(@"ax_enumeration_failed"); }
    [nodes addObject:guiNode(nodes.count, role, elementLabel(element), elementEnabled(element),
      focused != NULL && CFEqual(focused, element), secure, secure ? NO : browserNavigationElement(element, bundleId))];
  }
  if (focused != NULL) CFRelease(focused);
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_index": @0, @"window_title": title, @"window_identity": target.identity, @"focused": @YES,
    @"nodes": nodes, @"truncated": @(truncated) });
}

static int performAxAction(GuiWindowTarget *target, int argc, const char *argv[]) {
  NSString *bundleId = target.application.bundleIdentifier, *title = target.title;
  pid_t pid = target.application.processIdentifier;
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  NSInteger index;
  if (argc != 10 || !parseNumber(argv[5], 0, 1999, &index)) return fail(@"invalid_request");
  BOOL truncated = NO;
  NSArray *elements = windowElements(pid, target.axWindow, 2000, &truncated);
  if (elements == nil || index >= (NSInteger)elements.count) return fail(@"stale_target");
  AXUIElementRef element = (__bridge AXUIElementRef)elements[index];
  NSString *role = attributeText(element, kAXRoleAttribute);
  NSString *label = elementLabel(element);
  if (secureElement(element)) return fail(@"secure_target");
  NSString *blocked = approvedElementAncestryBlockReason(target, element);
  if (blocked != nil) return fail(blocked);
  if (![role isEqualToString:[NSString stringWithUTF8String:argv[6]]] ||
      ![label isEqualToString:[NSString stringWithUTF8String:argv[7]]] ||
      !elementEnabled(element)) return fail(@"stale_target");
  NSString *action = [NSString stringWithUTF8String:argv[8]];
  NSDictionary *actions = @{ @"press": (__bridge id)kAXPressAction, @"increment": (__bridge id)kAXIncrementAction,
    @"decrement": (__bridge id)kAXDecrementAction, @"show_menu": (__bridge id)kAXShowMenuAction };
  AXError error;
  if ([action isEqualToString:@"focus"] || [action isEqualToString:@"select"]) {
    error = AXUIElementSetAttributeValue(element, [action isEqualToString:@"focus"] ? kAXFocusedAttribute : kAXSelectedAttribute, kCFBooleanTrue);
  } else if (actions[action] != nil) error = AXUIElementPerformAction(element, (__bridge CFStringRef)actions[action]);
  else return fail(@"action_unsupported");
  if (error != kAXErrorSuccess) return fail(@"execution_failed");
  usleep(250000);
  NSString *reason = @"stale_target";
  if (resolveGuiWindow(bundleId, @"", NO, target.identity, &reason) == nil) return fail(reason);
  if (secureElement(element) ||
      ![attributeText(element, kAXRoleAttribute) isEqualToString:role] || ![elementLabel(element) isEqualToString:label]) return fail(@"stale_target");
  blocked = approvedElementAncestryBlockReason(target, element);
  if (blocked != nil) return fail(blocked);
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_index": @0, @"window_title": title, @"window_identity": target.identity, @"element_index": @(index), @"role": role,
    @"enabled": @(elementEnabled(element)),
    @"focused": @(attributeBool(element, kAXFocusedAttribute, NO)), @"secure": @NO, @"accepted": @YES });
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

static NSString *focusedInputBlockReason(GuiWindowTarget *target, AXUIElementRef expected,
                                         NSString *expectedRole, NSString *expectedLabel) {
  NSString *reason = @"stale_target";
  if (!readGuiFocusedWindow(target.application, target.axWindow, &reason)) return reason;
  if (sensitiveTitle(attributeText((__bridge AXUIElementRef)target.axWindow, kAXTitleAttribute))) return @"target_denied";
  AXUIElementRef focused = focusedElement(target.application.processIdentifier);
  if (focused == NULL) return @"stale_target";
  if (secureElement(focused)) { CFRelease(focused); return @"secure_target"; }
  NSString *blocked = approvedElementAncestryBlockReason(target, focused);
  if (blocked != nil) { CFRelease(focused); return blocked; }
  NSString *role = attributeText(focused, kAXRoleAttribute);
  NSString *label = elementLabel(focused);
  CFTypeRef ownerWindow = NULL; pid_t pid = -1;
  AXUIElementCopyAttributeValue(focused, kAXWindowAttribute, &ownerWindow);
  BOOL owned = ownerWindow != NULL && CFEqual(ownerWindow, (__bridge CFTypeRef)target.axWindow) &&
    AXUIElementGetPid(focused, &pid) == kAXErrorSuccess && pid == target.application.processIdentifier;
  if (ownerWindow != NULL) CFRelease(ownerWindow);
  BOOL matched = expected != NULL && CFEqual(expected, focused) &&
    [role isEqualToString:expectedRole] && [label isEqualToString:expectedLabel];
  BOOL enabled = elementEnabled(focused);
  CFRelease(focused);
  if (!owned || !matched || !enabled) return @"stale_target";
  return textRole(role) ? nil : @"target_unsupported";
}

static int typeIntoFocused(GuiWindowTarget *target, const char *expectedRole, const char *expectedLabel,
                            NSInteger expectedIndex) {
  NSString *bundleId = target.application.bundleIdentifier, *title = target.title;
  pid_t pid = target.application.processIdentifier;
  if (!AXIsProcessTrusted()) return fail(@"accessibility_permission");
  AXUIElementRef focused = focusedElement(pid);
  if (focused == NULL) return fail(@"stale_target");
  NSString *role = attributeText(focused, kAXRoleAttribute);
  NSString *label = elementLabel(focused);
  id inputElement = (__bridge id)focused;
  NSString *blocked = focusedInputBlockReason(target, focused,
    [NSString stringWithUTF8String:expectedRole], [NSString stringWithUTF8String:expectedLabel]);
  if (blocked == nil && expectedIndex >= 0) {
    BOOL truncated = NO;
    NSArray *elements = windowElements(pid, target.axWindow, 2000, &truncated);
    if (expectedIndex >= (NSInteger)elements.count || !CFEqual((__bridge CFTypeRef)elements[expectedIndex], focused))
      blocked = @"stale_target";
  }
  id navigationElement = blocked == nil && browserNavigationElement(focused, bundleId) ? (__bridge id)focused : nil;
  CFRelease(focused);
  if (blocked != nil) return fail(blocked);
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
  BOOL navigation = [request[@"navigation"] boolValue];
  // Delegation provenance must still hold at dispatch, before typing or Enter.
  if (!navigationDispatchAllowed(navigation, navigationElement != nil, text, keys, [request[@"submit"] boolValue]))
    return fail(@"secure_target");
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
  // Parsing input can take time. Revalidate authorization and live focus again,
  // and before each bounded event pair, instead of trusting observation flags.
  NSString *reason = @"stale_target";
  if (resolveGuiWindow(bundleId, @"", NO, target.identity, &reason) == nil) return fail(reason);
  for (NSUInteger offset = 0; offset < text.length;) {
    blocked = focusedInputBlockReason(target, (__bridge AXUIElementRef)inputElement, role, label);
    if (blocked != nil) return fail(blocked);
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
  for (NSString *key in keys) {
    blocked = focusedInputBlockReason(target, (__bridge AXUIElementRef)inputElement, role, label);
    if (blocked != nil) return fail(blocked);
    if (!postKey(keyCodes[key].unsignedShortValue, 0)) return fail(@"execution_failed");
  }
  if ([request[@"submit"] boolValue]) {
    blocked = focusedInputBlockReason(target, (__bridge AXUIElementRef)inputElement, role, label);
    if (blocked != nil) return fail(blocked);
    if (!postKey(36, 0)) return fail(@"execution_failed");
  }
  // Keep the event sender alive while WindowServer delivers the queued input.
  usleep(250000);
  AXUIElementRef after = NULL;
  BOOL focusConfirmed = NO;
  NSString *postRole = nil;
  if (navigation) {
    focusConfirmed = NO;
    for (NSUInteger attempt = 0; attempt < 30; attempt++) {
      GuiWindowTarget *current = resolveGuiWindow(bundleId, @"", NO, target.identity, &reason);
      if (current == nil) return fail(reason);
      after = focusedElement(pid);
      CFTypeRef ownerWindow = NULL;
      if (after != NULL) AXUIElementCopyAttributeValue(after, kAXWindowAttribute, &ownerWindow);
      BOOL owned = ownerWindow != NULL && CFEqual(ownerWindow, (__bridge CFTypeRef)current.axWindow);
      BOOL verified = owned && approvedElementAncestryBlockReason(current, after) == nil && !secureElement(after) &&
        browserNavigationElement((__bridge AXUIElementRef)navigationElement, bundleId) &&
        navigationAddressMatches(text, attributeText((__bridge AXUIElementRef)navigationElement, kAXValueAttribute));
      if (verified) postRole = attributeText(after, kAXRoleAttribute);
      if (ownerWindow != NULL) CFRelease(ownerWindow);
      if (after != NULL) CFRelease(after);
      if (verified && postRole.length > 0 && postRole.length <= 128) { focusConfirmed = YES; break; }
      [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    if (!focusConfirmed) return fail(@"navigation_unverified");
  } else {
    blocked = focusedInputBlockReason(target, (__bridge AXUIElementRef)inputElement, role, label);
    if (blocked != nil) return fail(blocked);
    if (resolveGuiWindow(bundleId, @"", NO, target.identity, &reason) == nil) return fail(reason);
    focusConfirmed = YES;
  }
  NSMutableDictionary *result = [@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_index": @0, @"window_title": title, @"window_identity": target.identity, @"element_index": @(MAX(0, expectedIndex)), @"role": role,
    @"characters_accepted": @(text.length), @"keys_accepted": keys,
    @"submitted": request[@"submit"], @"focus_confirmed": @YES, @"secure": @NO } mutableCopy];
  if (navigation) { result[@"navigation_verified"] = @YES; result[@"post_role"] = postRole; }
  return emit(result);
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
  return sensitiveTitle(identity) || sensitiveAction(identity) || [identity localizedCaseInsensitiveContainsString:@"secure"];
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

static int performAction(GuiWindowTarget *target, int argc, const char *argv[]) {
  NSString *bundleId = target.application.bundleIdentifier, *windowHint = target.title;
  NSArray<NSDictionary *> *windows = target.windows;
  NSRunningApplication *frontmost = target.application;
  if (argc != 13) return fail(@"invalid_request");
  NSString *action = [NSString stringWithUTF8String:argv[5]];
  NSString *key = [NSString stringWithUTF8String:argv[10]];
  NSInteger x, y, dx, dy, waitMs;
  if (!parseNumber(argv[6], -20000, 20000, &x) || !parseNumber(argv[7], -20000, 20000, &y) ||
      !parseNumber(argv[8], -1000, 1000, &dx) || !parseNumber(argv[9], -1000, 1000, &dy) ||
      !parseNumber(argv[11], 0, 2000, &waitMs)) return fail(@"invalid_request");
  NSUInteger selectedPosition = target.position;
  NSDictionary *selected = target.cgWindow;
  CGRect bounds = CGRectZero;
  CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)selected[(id)kCGWindowBounds], &bounds);
  CGPoint point = CGPointMake(x, y);
  BOOL pointerAction = [@[@"click", @"double_click", @"right_click", @"move_pointer", @"scroll"] containsObject:action];
  if (pointerAction && (!CGRectContainsPoint(bounds, point) || !isDesktopPoint(point))) return fail(@"outside_window");
  for (NSUInteger index = 0; index < selectedPosition; index++) {
    NSDictionary *overlay = windows[index];
    if ([overlay[(id)kCGWindowOwnerPID] intValue] == frontmost.processIdentifier) continue;
    CGRect overlayBounds = CGRectZero;
    CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)overlay[(id)kCGWindowBounds], &overlayBounds);
    // Dock can publish a full-display layer-20 window that does not receive clicks.
    // Exempt it only when the system-wide hit test resolves to this application.
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
  NSString *reason = @"stale_target";
  if (resolveGuiWindow(bundleId, @"", NO, target.identity, &reason) == nil) return fail(reason);
  return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
    @"window_title": windowHint, @"window_identity": target.identity, @"action": action, @"accepted": @YES, @"focused": @YES });
}

#import "gui_desktop.h"

static int executeGui(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc == 2 && strcmp(argv[1], "capabilities") == 0) {
      return emit(@{ @"status": @"ok", @"version": @"0.3",
        @"features": @{ @"ordinary_apps": @YES, @"bounded_global_coordinates": @YES, @"desktop_surfaces": @YES } });
    }
    if (argc == 2 && strcmp(argv[1], "permission") == 0) {
      return emit(@{ @"status": @"ok", @"accessibility": @((BOOL)AXIsProcessTrusted()),
        @"screen_recording": @((BOOL)CGPreflightScreenCaptureAccess()) });
    }
    if (argc == 2 && strcmp(argv[1], "request_accessibility") == 0) {
      NSDictionary *options = @{ (__bridge id)kAXTrustedCheckOptionPrompt: @YES };
      return emit(@{ @"status": @"ok", @"accessibility": @((BOOL)AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options)) });
    }
    if (argc == 2 && strcmp(argv[1], "request_screen_recording") == 0) {
      return emit(@{ @"status": @"ok", @"screen_recording": @((BOOL)CGRequestScreenCaptureAccess()) });
    }
    if (argc < 4 || (strcmp(argv[1], "capture") != 0 && strcmp(argv[1], "action") != 0 &&
        strcmp(argv[1], "inspect") != 0 && strcmp(argv[1], "type") != 0 &&
        strcmp(argv[1], "focus") != 0 && strcmp(argv[1], "ax_action") != 0)) return fail(@"invalid_request");
    NSString *mode = strcmp(argv[1], "capture") == 0 ? [NSString stringWithUTF8String:argv[2]] : @"";
    NSString *bundleId = [NSString stringWithUTF8String:argv[3]];
    NSString *windowHint = argc > 4 ? [NSString stringWithUTF8String:argv[4]] : @"";
    if ([bundleId isEqualToString:@"dev.macoperator.desktop"]) return executeGuiDesktop(argc, argv);
    if ((strcmp(argv[1], "capture") == 0 && ![@[@"screen", @"active_window", @"selected_window"] containsObject:mode]) ||
        !isGuiApplicationBundle(bundleId) ||
        (windowHint.length > 0 && sensitiveTitle(windowHint))) return fail(@"target_denied");
    if (strcmp(argv[1], "capture") == 0 && !CGPreflightScreenCaptureAccess()) return fail(@"screen_recording_permission");
    BOOL focus = strcmp(argv[1], "focus") == 0;
    BOOL inspect = strcmp(argv[1], "inspect") == 0;
    BOOL capture = strcmp(argv[1], "capture") == 0;
    BOOL action = strcmp(argv[1], "action") == 0;
    BOOL axAction = strcmp(argv[1], "ax_action") == 0;
    BOOL type = strcmp(argv[1], "type") == 0;
    if ((focus && argc != 5) || (inspect && argc != 6 && argc != 7) || (capture && argc != 6) ||
        (action && argc != 13) || (axAction && argc != 10) || (type && argc != 8 && argc != 9)) return fail(@"invalid_request");
    NSString *expected = focus || (inspect && argc == 6) ? @"" : [NSString stringWithUTF8String:argv[argc - 1]];
    if (!focus && !inspect && expected.length == 0) return fail(@"invalid_request");
    NSString *reason = @"window_correlation_failed";
    GuiWindowTarget *target = resolveGuiWindow(bundleId, windowHint, focus, expected, &reason);
    if (target == nil) return fail(reason);
    if (focus) return emit(@{ @"status": @"ok", @"app_id": [@"bundle:" stringByAppendingString:bundleId],
      @"window_index": @0, @"window_title": target.title, @"window_identity": target.identity, @"focused": @YES });
    if (axAction) return performAxAction(target, argc, argv);
    if (action) return performAction(target, argc, argv);
    if (type) {
      NSInteger index = -1;
      if (argc == 9 && !parseNumber(argv[7], 0, 1999, &index)) return fail(@"invalid_request");
      return typeIntoFocused(target, argv[5], argv[6], index);
    }
    if (inspect) {
      NSInteger maxNodes;
      if (!parseNumber(argv[5], 1, 2000, &maxNodes)) return fail(@"invalid_request");
      return inspectUi(target, maxNodes);
    }
    NSArray<NSDictionary *> *windows = target.windows;
    NSDictionary *selected = target.cgWindow;
    NSUInteger selectedPosition = target.position;
    NSString *title = target.title;
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
        BOOL sensitive = sensitiveTitle(window[(id)kCGWindowName] ?: @"") || isSensitiveApplicationBundle(ownerId);
        NSString *reason = screenWindowBlockReason(index < selectedPosition, layer, bounds, overlayBounds, sensitive);
        if (reason != nil) return fail(reason);
      }
    }
    CGImageRef image = captureImage(mode, [selected[(id)kCGWindowNumber] unsignedIntValue]);
    if (image == NULL) return fail(@"capture_failed");
    if (resolveGuiWindow(bundleId, @"", NO, target.identity, &reason) == nil) {
      CGImageRelease(image); return fail(reason);
    }
    size_t imageWidth = CGImageGetWidth(image);
    size_t imageHeight = CGImageGetHeight(image);
    NSData *jpeg = jpegForImage(image, 1600);
    CGImageRelease(image);
    if (jpeg == nil) return fail(@"image_limit");
    CGDirectDisplayID display = CGMainDisplayID();
    return emit(@{
      @"status": @"ok", @"mode": mode,
      @"app_id": [@"bundle:" stringByAppendingString:bundleId],
      @"window_title": title, @"window_identity": target.identity,
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
