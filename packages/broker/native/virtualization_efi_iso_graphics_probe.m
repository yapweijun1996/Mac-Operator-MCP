// Development-only probe; do not expose through MCP or the production runner.
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#import <Vision/Vision.h>
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *kExpectedIsoSha256 =
    "a57ba668b5f6b17a670fcf8e799d5d7fe43766ed086d6ce2927b0625bf43dbf6";
static const unsigned long long kExpectedIsoBytes = 93304832ULL;

static BOOL HasVirtualizationEntitlement(void) {
  SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
  if (task == NULL) return NO;
  CFErrorRef error = NULL;
  CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.virtualization"), &error);
  const BOOL entitled = value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
      CFBooleanGetValue((CFBooleanRef)value);
  if (value != NULL) CFRelease(value);
  if (error != NULL) CFRelease(error);
  CFRelease(task);
  return entitled;
}

static BOOL HashRegularFile(const char *path, char output[CC_SHA256_DIGEST_LENGTH * 2 + 1],
    unsigned long long *size) {
  const int descriptor = open(path, O_RDONLY | O_NOFOLLOW);
  if (descriptor < 0) return NO;
  struct stat metadata;
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 1) {
    close(descriptor);
    return NO;
  }

  CC_SHA256_CTX context;
  if (CC_SHA256_Init(&context) != 1) {
    close(descriptor);
    return NO;
  }
  unsigned char buffer[64 * 1024];
  for (;;) {
    const ssize_t count = read(descriptor, buffer, sizeof(buffer));
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      close(descriptor);
      return NO;
    }
    if (CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1) {
      close(descriptor);
      return NO;
    }
  }
  close(descriptor);

  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  if (CC_SHA256_Final(digest, &context) != 1) return NO;
  static const char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof(digest); ++index) {
    output[index * 2] = hex[digest[index] >> 4];
    output[index * 2 + 1] = hex[digest[index] & 0x0f];
  }
  output[sizeof(digest) * 2] = '\0';
  *size = (unsigned long long)metadata.st_size;
  return YES;
}

static NSString *StateName(VZVirtualMachineState state) {
  switch (state) {
    case VZVirtualMachineStateStopped: return @"stopped";
    case VZVirtualMachineStateRunning: return @"running";
    case VZVirtualMachineStatePaused: return @"paused";
    case VZVirtualMachineStateError: return @"error";
    case VZVirtualMachineStateStarting: return @"starting";
    case VZVirtualMachineStatePausing: return @"pausing";
    case VZVirtualMachineStateResuming: return @"resuming";
    case VZVirtualMachineStateStopping: return @"stopping";
    case VZVirtualMachineStateSaving: return @"saving";
    case VZVirtualMachineStateRestoring: return @"restoring";
  }
  return @"unknown";
}

static BOOL ContainsGuestMarker(NSString *text) {
  NSString *lowercase = text.lowercaseString;
  return [lowercase containsString:@"alpine linux"] ||
      [lowercase containsString:@"welcome to alpine"] ||
      [lowercase containsString:@"linux version "] ||
      [lowercase containsString:@"localhost login:"];
}

@interface AlpineISOGraphicsProbe : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) VZVirtualMachineConfiguration *configuration;
@property(nonatomic, copy) NSString *isoSha256;
@property(nonatomic, copy) NSString *screenshotPath;
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) VZVirtualMachineView *vmView;
@property(nonatomic, strong) VZVirtualMachine *machine;
@property(nonatomic, copy) NSString *stateAfterStart;
@property(nonatomic, copy) NSString *stateAtCapture;
@property(nonatomic, copy) NSString *stateAfterStop;
@property(nonatomic, copy) NSString *ocrText;
@property(nonatomic, copy) NSString *captureError;
@property(nonatomic, copy) NSString *stopError;
@property(nonatomic) BOOL startSucceeded;
@property(nonatomic) BOOL frameCaptured;
@property(nonatomic) BOOL guestMarkerObserved;
@property(nonatomic) BOOL stopAttempted;
@property(nonatomic) BOOL stopPossible;
@property(nonatomic) BOOL stopSucceeded;
@property(nonatomic) BOOL finished;
@property(nonatomic) int exitStatus;
@end

@implementation AlpineISOGraphicsProbe

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  self.machine = [[VZVirtualMachine alloc] initWithConfiguration:self.configuration];
  self.window = [[NSWindow alloc]
      initWithContentRect:NSMakeRect(0, 0, 1024, 768)
      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable
      backing:NSBackingStoreBuffered
      defer:NO];
  self.window.title = @"Disposable Alpine VM Readiness Probe";
  self.vmView = [[VZVirtualMachineView alloc] initWithFrame:self.window.contentView.bounds];
  self.vmView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  self.vmView.virtualMachine = self.machine;
  self.window.contentView = self.vmView;
  [self.window center];
  [self.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];

  [self.machine startWithCompletionHandler:^(NSError *error) {
    self.stateAfterStart = StateName(self.machine.state);
    self.startSucceeded = error == nil && self.machine.state == VZVirtualMachineStateRunning;
    if (error != nil) {
      self.captureError = error.localizedDescription ?: @"VM start failed";
      [self finishAndStopIfSafe];
      return;
    }
    [NSTimer scheduledTimerWithTimeInterval:15.0
        target:self
        selector:@selector(captureGuestFrame)
        userInfo:nil
        repeats:NO];
  }];

  [NSTimer scheduledTimerWithTimeInterval:45.0
      target:self
      selector:@selector(handleWatchdog)
      userInfo:nil
      repeats:NO];
}

- (void)captureGuestFrame {
  if (self.finished) return;
  self.stateAtCapture = StateName(self.machine.state);
  if (self.machine.state != VZVirtualMachineStateRunning) {
    self.captureError = @"VM was not running at the frame-capture checkpoint";
    [self finishAndStopIfSafe];
    return;
  }

  NSBitmapImageRep *frame = [self.vmView bitmapImageRepForCachingDisplayInRect:self.vmView.bounds];
  [self.vmView cacheDisplayInRect:self.vmView.bounds toBitmapImageRep:frame];
  CGImageRef image = frame.CGImage;
  if (image == NULL) {
    self.captureError = @"Could not capture the VM window framebuffer";
    [self finishAndStopIfSafe];
    return;
  }

  CFURLRef image_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault, (__bridge CFStringRef)self.screenshotPath, kCFURLPOSIXPathStyle, false);
  CGImageDestinationRef destination = image_url == NULL ? NULL :
      CGImageDestinationCreateWithURL(image_url, CFSTR("public.png"), 1, NULL);
  if (destination != NULL) {
    CGImageDestinationAddImage(destination, image, NULL);
    self.frameCaptured = CGImageDestinationFinalize(destination);
    CFRelease(destination);
  }
  if (image_url != NULL) CFRelease(image_url);

  VNRecognizeTextRequest *request = [[VNRecognizeTextRequest alloc] init];
  request.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
  request.recognitionLanguages = @[ @"en-US" ];
  VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:image options:@{}];
  NSError *recognition_error = nil;
  const BOOL recognition_succeeded = [handler performRequests:@[ request ] error:&recognition_error];
  NSMutableArray<NSString *> *lines = [NSMutableArray array];
  NSUInteger recognized_characters = 0;
  if (recognition_succeeded) {
    for (VNRecognizedTextObservation *observation in request.results) {
      VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
      if (candidate != nil && candidate.string.length > 0 && recognized_characters < 8000) {
        [lines addObject:candidate.string];
        recognized_characters += candidate.string.length;
      }
    }
  }
  self.ocrText = [lines componentsJoinedByString:@"\n"];
  self.guestMarkerObserved = ContainsGuestMarker(self.ocrText ?: @"");
  if (!self.frameCaptured && recognition_error != nil) {
    self.captureError = recognition_error.localizedDescription ?: @"Framebuffer OCR failed";
  }
  [self finishAndStopIfSafe];
}

- (void)handleWatchdog {
  if (self.finished) return;
  if (self.captureError.length == 0) self.captureError = @"VM readiness probe exceeded 45 seconds";
  [self finishAndStopIfSafe];
}

- (void)finishAndStopIfSafe {
  if (self.finished) return;
  if (self.machine.state == VZVirtualMachineStateRunning && self.machine.canStop) {
    self.stopPossible = YES;
    self.stopAttempted = YES;
    [self.machine stopWithCompletionHandler:^(NSError *error) {
      self.stopError = error.localizedDescription ?: @"";
      self.stateAfterStop = StateName(self.machine.state);
      self.stopSucceeded = error == nil && self.machine.state == VZVirtualMachineStateStopped;
      [self finishAndExit];
    }];
    return;
  }
  self.stopPossible = self.machine.canStop;
  self.stateAfterStop = StateName(self.machine.state);
  [self finishAndExit];
}

- (void)finishAndExit {
  if (self.finished) return;
  self.finished = YES;
  self.exitStatus = self.startSucceeded && self.frameCaptured &&
      self.guestMarkerObserved && self.stopSucceeded ? 0 : 8;

  NSDictionary *record = @{
    @"framework": @"Virtualization.framework",
    @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
    @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
    @"boot_loader": @"VZEFIBootLoader",
    @"boot_media": @"read-only USB mass-storage ISO",
    @"iso_sha256": self.isoSha256 ?: @"",
    @"iso_attachment_read_only": @YES,
    @"graphics_device": @"VZVirtioGraphicsDeviceConfiguration",
    @"network_devices": @0,
    @"directory_sharing_devices": @0,
    @"socket_devices": @0,
    @"serial_ports": @0,
    @"state_after_start": self.stateAfterStart ?: @"unknown",
    @"start_succeeded": @(self.startSucceeded),
    @"state_at_capture": self.stateAtCapture ?: @"not_captured",
    @"frame_captured": @(self.frameCaptured),
    @"screenshot_path": self.frameCaptured ? self.screenshotPath : @"",
    @"guest_marker_observed": @(self.guestMarkerObserved),
    @"ocr_text": self.ocrText ?: @"",
    @"capture_error": self.captureError ?: @"",
    @"hard_stop_possible": @(self.stopPossible),
    @"hard_stop_attempted": @(self.stopAttempted),
    @"hard_stop_completed": @(self.stopSucceeded),
    @"stop_error": self.stopError ?: @"",
    @"state_after_stop": self.stateAfterStop ?: @"not_stopped"
  };
  NSError *json_error = nil;
  NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:&json_error];
  if (json != nil) {
    fwrite(json.bytes, 1, json.length, stdout);
    fputc('\n', stdout);
  } else {
    fputs("Could not serialize the VM graphics probe result\n", stderr);
    self.exitStatus = 1;
  }
  [self.window orderOut:nil];
  [NSApp terminate:nil];
}

@end

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 4) {
      fputs("Usage: virtualization_efi_iso_graphics_probe <official-iso> <new-variable-store> <new-screenshot.png>\n", stderr);
      return 2;
    }
    if (!HasVirtualizationEntitlement()) {
      fputs("Virtualization entitlement is absent from the probe process\n", stderr);
      return 3;
    }

    char iso_sha256[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned long long iso_bytes = 0;
    if (!HashRegularFile(argv[1], iso_sha256, &iso_bytes) ||
        iso_bytes != kExpectedIsoBytes || strcmp(iso_sha256, kExpectedIsoSha256) != 0) {
      fputs("ISO must be the pinned official Alpine virt ARM64 image\n", stderr);
      return 4;
    }
    struct stat screenshot_metadata;
    if (lstat(argv[3], &screenshot_metadata) == 0 || errno != ENOENT) {
      fputs("Screenshot output path must be new and must not already exist\n", stderr);
      return 5;
    }

    NSString *iso_path = [NSString stringWithUTF8String:argv[1]];
    NSString *variable_store_path = [NSString stringWithUTF8String:argv[2]];
    NSString *screenshot_path = [NSString stringWithUTF8String:argv[3]];
    if (iso_path == nil || variable_store_path == nil || screenshot_path == nil ||
        ![VZVirtualMachine isSupported]) {
      fputs("Virtualization host or probe path is unavailable\n", stderr);
      return 6;
    }

    NSError *attachment_error = nil;
    VZDiskImageStorageDeviceAttachment *attachment =
        [[VZDiskImageStorageDeviceAttachment alloc]
            initWithURL:[NSURL fileURLWithPath:iso_path]
            readOnly:YES
            error:&attachment_error];
    if (attachment == nil || !attachment.readOnly) {
      fprintf(stderr, "Could not attach the pinned ISO read-only: %s\n",
          attachment_error.localizedDescription.UTF8String ?: "unknown attachment error");
      return 7;
    }

    NSError *variable_store_error = nil;
    VZEFIVariableStore *variable_store = [[VZEFIVariableStore alloc]
        initCreatingVariableStoreAtURL:[NSURL fileURLWithPath:variable_store_path]
        options:0
        error:&variable_store_error];
    if (variable_store == nil) {
      fprintf(stderr, "Could not create a fresh EFI variable store: %s\n",
          variable_store_error.localizedDescription.UTF8String ?: "unknown variable-store error");
      return 7;
    }

    VZUSBMassStorageDeviceConfiguration *iso_device =
        [[VZUSBMassStorageDeviceConfiguration alloc] initWithAttachment:attachment];
    VZXHCIControllerConfiguration *usb_controller = [[VZXHCIControllerConfiguration alloc] init];
    usb_controller.usbDevices = @[ iso_device ];

    VZVirtioGraphicsDeviceConfiguration *graphics = [[VZVirtioGraphicsDeviceConfiguration alloc] init];
    graphics.scanouts = @[
      [[VZVirtioGraphicsScanoutConfiguration alloc] initWithWidthInPixels:1024 heightInPixels:768]
    ];
    VZEFIBootLoader *boot_loader = [[VZEFIBootLoader alloc] init];
    boot_loader.variableStore = variable_store;

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = 2;
    configuration.memorySize = 1024ULL * 1024ULL * 1024ULL;
    configuration.usbControllers = @[ usb_controller ];
    configuration.graphicsDevices = @[ graphics ];
    configuration.keyboards = @[];
    configuration.pointingDevices = @[];
    configuration.audioDevices = @[];
    configuration.networkDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.socketDevices = @[];
    configuration.serialPorts = @[];
    configuration.storageDevices = @[];

    NSError *validation_error = nil;
    if (![configuration validateWithError:&validation_error]) {
      fprintf(stderr, "Virtualization configuration is invalid: %s\n",
          validation_error.localizedDescription.UTF8String ?: "unknown configuration error");
      return 8;
    }

    NSApplication *application = [NSApplication sharedApplication];
    [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
    AlpineISOGraphicsProbe *probe = [[AlpineISOGraphicsProbe alloc] init];
    probe.configuration = configuration;
    probe.isoSha256 = [NSString stringWithUTF8String:iso_sha256];
    probe.screenshotPath = screenshot_path;
    application.delegate = probe;
    [application run];
    return probe.exitStatus;
  }
}
