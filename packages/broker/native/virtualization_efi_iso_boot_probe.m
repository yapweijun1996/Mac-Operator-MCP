// Development-only probe; do not expose through MCP or the production runner.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
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

static BOOL WaitFor(dispatch_semaphore_t semaphore, NSTimeInterval timeout_seconds) {
  const int64_t nanoseconds = (int64_t)(timeout_seconds * (double)NSEC_PER_SEC);
  return dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
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

static int EmitRecord(NSDictionary *record) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:&error];
  if (data == nil) {
    fputs("Virtualization EFI ISO probe could not encode its result\n", stderr);
    return 1;
  }
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 3) {
      fputs("Usage: virtualization_efi_iso_boot_probe <official-iso> <new-variable-store>\n", stderr);
      return 2;
    }
    if (!HasVirtualizationEntitlement()) {
      fputs("Virtualization entitlement is absent from the probe process\n", stderr);
      return 3;
    }

    char iso_sha256[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned long long iso_bytes = 0;
    const BOOL iso_is_valid = HashRegularFile(argv[1], iso_sha256, &iso_bytes) &&
        iso_bytes == kExpectedIsoBytes && strcmp(iso_sha256, kExpectedIsoSha256) == 0;
    if (!iso_is_valid) {
      fputs("ISO must be the pinned official Alpine virt ARM64 image\n", stderr);
      return 4;
    }

    NSString *iso_path = [NSString stringWithUTF8String:argv[1]];
    NSString *variable_store_path = [NSString stringWithUTF8String:argv[2]];
    if (iso_path == nil || variable_store_path == nil || ![VZVirtualMachine isSupported]) {
      fputs("Virtualization host or probe path is unavailable\n", stderr);
      return 5;
    }

    NSError *attachment_error = nil;
    VZDiskImageStorageDeviceAttachment *attachment =
        [[VZDiskImageStorageDeviceAttachment alloc]
            initWithURL:[NSURL fileURLWithPath:iso_path]
            readOnly:YES
            error:&attachment_error];
    if (attachment == nil || !attachment.readOnly) {
      NSDictionary *record = @{
        @"configuration_valid": @NO,
        @"iso_attachment_read_only": @(attachment.readOnly),
        @"attachment_error": attachment_error.localizedDescription ?: @"read-only ISO attachment failed",
        @"vm_object_created": @NO,
        @"vm_boot_attempted": @NO
      };
      return EmitRecord(record) == 0 ? 6 : 1;
    }

    NSError *variable_store_error = nil;
    VZEFIVariableStore *variable_store = [[VZEFIVariableStore alloc]
        initCreatingVariableStoreAtURL:[NSURL fileURLWithPath:variable_store_path]
        options:0
        error:&variable_store_error];
    if (variable_store == nil) {
      NSDictionary *record = @{
        @"configuration_valid": @NO,
        @"variable_store_error": variable_store_error.localizedDescription ?: @"EFI variable-store creation failed",
        @"vm_object_created": @NO,
        @"vm_boot_attempted": @NO
      };
      return EmitRecord(record) == 0 ? 6 : 1;
    }

    VZUSBMassStorageDeviceConfiguration *iso_device =
        [[VZUSBMassStorageDeviceConfiguration alloc] initWithAttachment:attachment];
    VZXHCIControllerConfiguration *usb_controller = [[VZXHCIControllerConfiguration alloc] init];
    usb_controller.usbDevices = @[ iso_device ];

    VZEFIBootLoader *boot_loader = [[VZEFIBootLoader alloc] init];
    boot_loader.variableStore = variable_store;

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = 2;
    configuration.memorySize = 1024ULL * 1024ULL * 1024ULL;
    configuration.usbControllers = @[ usb_controller ];
    configuration.networkDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.socketDevices = @[];
    configuration.serialPorts = @[];

    NSError *validation_error = nil;
    if (![configuration validateWithError:&validation_error]) {
      NSDictionary *record = @{
        @"configuration_valid": @NO,
        @"validation_error": validation_error.localizedDescription ?: @"configuration validation failed",
        @"vm_object_created": @NO,
        @"vm_boot_attempted": @NO
      };
      return EmitRecord(record) == 0 ? 7 : 1;
    }

    dispatch_queue_t vm_queue = dispatch_queue_create("com.mac-operator.virtualization-efi-iso-probe", DISPATCH_QUEUE_SERIAL);
    VZVirtualMachine *machine = [[VZVirtualMachine alloc] initWithConfiguration:configuration queue:vm_queue];
    dispatch_semaphore_t start_semaphore = dispatch_semaphore_create(0);
    __block NSError *start_error = nil;
    __block NSString *state_after_start = @"unknown";
    __block BOOL start_state_running = NO;
    dispatch_async(vm_queue, ^{
      [machine startWithCompletionHandler:^(NSError *error) {
        start_error = error;
        const VZVirtualMachineState state = machine.state;
        state_after_start = StateName(state);
        start_state_running = state == VZVirtualMachineStateRunning;
        dispatch_semaphore_signal(start_semaphore);
      }];
    });
    const BOOL start_completed = WaitFor(start_semaphore, 45.0);
    const BOOL start_succeeded = start_completed && start_error == nil && start_state_running;

    if (start_succeeded) usleep(10 * 1000 * 1000);

    dispatch_semaphore_t stop_semaphore = dispatch_semaphore_create(0);
    __block NSError *stop_error = nil;
    __block BOOL stop_attempted = NO;
    __block BOOL stop_possible = NO;
    __block BOOL state_stopped = NO;
    __block NSString *state_before_stop = @"not_checked";
    __block NSString *state_after_stop = @"not_attempted";
    if (start_succeeded) {
      dispatch_async(vm_queue, ^{
        const VZVirtualMachineState state = machine.state;
        state_before_stop = StateName(state);
        if (state == VZVirtualMachineStateStopped) {
          state_stopped = YES;
          dispatch_semaphore_signal(stop_semaphore);
          return;
        }
        if (state != VZVirtualMachineStateRunning) {
          state_after_stop = StateName(state);
          dispatch_semaphore_signal(stop_semaphore);
          return;
        }
        stop_possible = machine.canStop;
        if (!stop_possible) {
          dispatch_semaphore_signal(stop_semaphore);
          return;
        }
        stop_attempted = YES;
        [machine stopWithCompletionHandler:^(NSError *error) {
          stop_error = error;
          const VZVirtualMachineState stopped_state = machine.state;
          state_after_stop = StateName(stopped_state);
          state_stopped = stopped_state == VZVirtualMachineStateStopped;
          dispatch_semaphore_signal(stop_semaphore);
        }];
      });
    }
    const BOOL stop_completed = start_succeeded && WaitFor(stop_semaphore, 45.0);
    const BOOL stopped_readback = stop_completed && state_stopped;

    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"virtualization_supported": @YES,
      @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
      @"boot_loader": @"VZEFIBootLoader",
      @"boot_media": @"read-only USB mass-storage ISO",
      @"iso_sha256": [NSString stringWithUTF8String:iso_sha256],
      @"iso_bytes": @(iso_bytes),
      @"iso_attachment_read_only": @(attachment.readOnly),
      @"configuration_valid": @YES,
      @"cpu_count": @2,
      @"memory_bytes": @(configuration.memorySize),
      @"network_devices": @0,
      @"directory_sharing_devices": @0,
      @"socket_devices": @0,
      @"serial_ports": @0,
      @"vm_object_created": @YES,
      @"vm_boot_attempted": @YES,
      @"start_completed": @(start_completed),
      @"start_succeeded": @(start_succeeded),
      @"state_after_start": state_after_start,
      @"start_error": start_error.localizedDescription ?: @"",
      @"start_error_domain": start_error.domain ?: @"",
      @"start_error_code": start_error == nil ? @0 : @(start_error.code),
      @"state_before_stop": state_before_stop,
      @"hard_stop_attempted": @(stop_attempted),
      @"hard_stop_possible": @(stop_possible),
      @"hard_stop_completed": @(stop_completed && stop_attempted && stop_error == nil),
      @"stop_error": stop_error.localizedDescription ?: @"",
      @"state_after_stop": state_after_stop,
      @"stopped_state_readback": @(stopped_readback)
    };
    const int output_status = EmitRecord(record);
    const BOOL success = start_succeeded && stop_completed && stop_error == nil && stopped_readback;
    return output_status != 0 ? output_status : (success ? 0 : 8);
  }
}
