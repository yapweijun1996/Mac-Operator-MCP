#import <AppKit/AppKit.h>

// Independent readback covers only controls created by this temporary fixture.
// Secure-field contents are never read or written to the state file.
@interface GuiReliabilityFixture : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) NSWindow *primary;
@property(nonatomic, strong) NSWindow *secondary;
@property(nonatomic, strong) NSTextView *editor;
@property(nonatomic, strong) NSSecureTextField *secureInput;
@property(nonatomic, strong) NSButton *checkbox;
@property(nonatomic, strong) NSComboBox *combo;
@property(nonatomic, strong) NSString *statePath;
@property(nonatomic, strong) NSString *commandPath;
@property(nonatomic, assign) NSInteger revision;
@property(nonatomic, assign) BOOL ignoreCheckbox;
@property(nonatomic, assign) NSInteger checkboxActivations;
@end

@implementation GuiReliabilityFixture
- (NSWindow *)window:(NSString *)title frame:(NSRect)frame {
  NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
    styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable
    backing:NSBackingStoreBuffered defer:NO];
  window.title = title;
  window.releasedWhenClosed = NO;
  return window;
}
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  NSArray<NSString *> *args = NSProcessInfo.processInfo.arguments;
  self.statePath = args[1]; self.commandPath = args[2];
  self.primary = [self window:@"MBA-MCP Fixture Primary" frame:NSMakeRect(100, 100, 650, 480)];
  NSView *content = self.primary.contentView;
  self.combo = [[NSComboBox alloc] initWithFrame:NSMakeRect(30, 410, 100, 26)];
  self.combo.accessibilityLabel = @"Font size";
  [self.combo addItemsWithObjectValues:@[@"12", @"14", @"18"]];
  self.combo.stringValue = @"12";
  [content addSubview:self.combo];
  NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(30, 150, 580, 235)];
  self.editor = [[NSTextView alloc] initWithFrame:scroll.bounds];
  self.editor.richText = NO;
  self.editor.accessibilityLabel = @"Ordinary fixture text";
  scroll.documentView = self.editor;
  scroll.hasVerticalScroller = YES;
  [content addSubview:scroll];
  self.checkbox = [[NSButton alloc] initWithFrame:NSMakeRect(30, 100, 220, 28)];
  [self.checkbox setButtonType:NSButtonTypeSwitch];
  self.checkbox.title = @"Fixture checkbox";
  self.checkbox.target = self;
  self.checkbox.action = @selector(checkboxClicked:);
  [content addSubview:self.checkbox];
  self.secureInput = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(30, 45, 230, 26)];
  self.secureInput.accessibilityLabel = @"Protected fixture input";
  [content addSubview:self.secureInput];
  self.secondary = [self window:@"MBA-MCP Fixture Secondary" frame:NSMakeRect(770, 100, 250, 240)];
  NSTextField *label = [NSTextField labelWithString:@"Owned second window"];
  label.frame = NSMakeRect(20, 150, 210, 30);
  [self.secondary.contentView addSubview:label];
  [self.primary makeKeyAndOrderFront:nil];
  [self.primary makeFirstResponder:self.editor];
  [NSTimer scheduledTimerWithTimeInterval:0.05 target:self selector:@selector(tick:) userInfo:nil repeats:YES];
  [self publish];
}
- (void)checkboxClicked:(id)sender {
  (void)sender;
  self.checkboxActivations += 1;
  if (self.ignoreCheckbox) self.checkbox.state = NSControlStateValueOff;
  [self publish];
}
- (NSDictionary *)pointFor:(NSView *)view {
  NSRect rect = [view.window convertRectToScreen:[view convertRect:view.bounds toView:nil]];
  CGFloat top = NSMaxY(NSScreen.screens.firstObject.frame);
  return @{ @"x": @(floor(NSMidX(rect))), @"y": @(floor(top - NSMidY(rect))) };
}
- (void)publish {
  NSDictionary *state = @{ @"ready": @YES, @"pid": @(NSProcessInfo.processInfo.processIdentifier),
    @"bundle_id": NSBundle.mainBundle.bundleIdentifier ?: @"", @"revision": @(self.revision),
    @"text": self.editor.string ?: @"", @"checked": @((BOOL)(self.checkbox.state == NSControlStateValueOn)),
    @"checkbox_activations": @(self.checkboxActivations),
    @"checkbox_present": @((BOOL)(self.checkbox.superview != nil)),
    @"checkbox_point": [self pointFor:self.checkbox], @"text_point": [self pointFor:self.editor],
    @"combo_point": [self pointFor:self.combo], @"secure_point": [self pointFor:self.secureInput] };
  NSData *data = [NSJSONSerialization dataWithJSONObject:state options:0 error:nil];
  [data writeToFile:self.statePath options:NSDataWritingAtomic error:nil];
}
- (void)tick:(NSTimer *)timer {
  (void)timer;
  NSData *data = [NSData dataWithContentsOfFile:self.commandPath];
  NSDictionary *command = data == nil ? nil : [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  if ([command isKindOfClass:NSDictionary.class] && [command[@"revision"] integerValue] > self.revision) {
    self.revision = [command[@"revision"] integerValue];
    NSString *operation = command[@"operation"];
    if ([operation isEqualToString:@"focus_text"]) [self.primary makeFirstResponder:self.editor];
    else if ([operation isEqualToString:@"focus_window"]) [self.primary makeFirstResponder:nil];
    else if ([operation isEqualToString:@"focus_secure"]) [self.primary makeFirstResponder:self.secureInput];
    else if ([operation isEqualToString:@"hide_checkbox"]) [self.checkbox removeFromSuperview];
    else if ([operation isEqualToString:@"show_checkbox"]) [self.primary.contentView addSubview:self.checkbox];
    else if ([operation isEqualToString:@"show_second"]) [self.secondary makeKeyAndOrderFront:nil];
    else if ([operation isEqualToString:@"focus_primary"]) [self.primary makeKeyAndOrderFront:nil];
    else if ([operation isEqualToString:@"unchanged_checkbox"]) { self.checkbox.state = NSControlStateValueOff; self.ignoreCheckbox = YES; }
    else if ([operation isEqualToString:@"changed_checkbox"]) { self.checkbox.state = NSControlStateValueOff; self.ignoreCheckbox = NO; }
    else if ([operation isEqualToString:@"clear_text"]) self.editor.string = @"";
    else if ([operation isEqualToString:@"quit"]) { [self publish]; [NSApp terminate:nil]; return; }
  }
  [self publish];
}
@end

int main(int argc, const char *argv[]) {
  (void)argv;
  @autoreleasepool {
    if (argc != 3) return 64;
    [NSApplication sharedApplication];
    NSApp.activationPolicy = NSApplicationActivationPolicyRegular;
    GuiReliabilityFixture *delegate = [GuiReliabilityFixture new];
    NSApp.delegate = delegate;
    [NSApp run];
  }
  return 0;
}
