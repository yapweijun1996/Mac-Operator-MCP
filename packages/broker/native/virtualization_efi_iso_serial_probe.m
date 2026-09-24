// Development-only probe; do not expose through MCP or the production runner.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *kExpectedIsoSha256 =
    "c78a31274e30d8df9181315f6d4fd5501b7d46461f9a43994465588ccc072f5b";
static const unsigned long long kExpectedIsoBytes = 93323264ULL;
static const NSUInteger kMaximumSerialBytes = 512 * 1024;

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

static double MonotonicSeconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0.0;
  return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static void DrainSerial(int descriptor, NSMutableData *output) {
  unsigned char buffer[4096];
  while (output.length < kMaximumSerialBytes) {
    const size_t capacity = MIN(sizeof(buffer), kMaximumSerialBytes - output.length);
    const ssize_t count = read(descriptor, buffer, capacity);
    if (count > 0) {
      [output appendBytes:buffer length:(NSUInteger)count];
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    break;
  }
}

static void CaptureSerialFor(int descriptor, NSMutableData *output, double duration_seconds) {
  const double deadline = MonotonicSeconds() + duration_seconds;
  struct pollfd event = { .fd = descriptor, .events = POLLIN, .revents = 0 };
  while (MonotonicSeconds() < deadline && output.length < kMaximumSerialBytes) {
    event.revents = 0;
    const int result = poll(&event, 1, 50);
    if (result > 0 && (event.revents & (POLLIN | POLLHUP)) != 0) DrainSerial(descriptor, output);
    else if (result < 0 && errno != EINTR) break;
  }
  DrainSerial(descriptor, output);
}

static BOOL WaitFor(dispatch_semaphore_t semaphore, double timeout_seconds) {
  const int64_t nanoseconds = (int64_t)(timeout_seconds * (double)NSEC_PER_SEC);
  return dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
}

static BOOL ContainsBytes(NSData *data, const char *needle) {
  const size_t needle_size = strlen(needle);
  if (needle_size == 0 || data.length < needle_size) return NO;
  const unsigned char *bytes = data.bytes;
  for (NSUInteger offset = 0; offset + needle_size <= data.length; ++offset) {
    if (memcmp(bytes + offset, needle, needle_size) == 0) return YES;
  }
  return NO;
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

static int EmitRecord(NSDictionary *record) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:&error];
  if (data == nil) {
    fputs("Virtualization EFI ISO serial probe could not encode its result\n", stderr);
    return 1;
  }
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 3) {
      fputs("Usage: virtualization_efi_iso_serial_probe <pinned-hvc0-iso> <new-variable-store>\n", stderr);
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
      fputs("ISO must match the pinned Alpine 3.24.2 ARM64 hvc0 probe image\n", stderr);
      return 4;
    }

    NSString *iso_path = [NSString stringWithUTF8String:argv[1]];
    NSString *variable_store_path = [NSString stringWithUTF8String:argv[2]];
    if (iso_path == nil || variable_store_path == nil || ![VZVirtualMachine isSupported]) {
      fputs("Virtualization host or probe path is unavailable\n", stderr);
      return 5;
    }

    int serial_pipe[2];
    if (pipe(serial_pipe) != 0) {
      fputs("Could not create the bounded guest-serial pipe\n", stderr);
      return 6;
    }
    int serial_input_pipe[2];
    if (pipe(serial_input_pipe) != 0) {
      close(serial_pipe[0]);
      close(serial_pipe[1]);
      fputs("Could not create the read-only guest-diagnostic input pipe\n", stderr);
      return 6;
    }
    const int pipe_flags = fcntl(serial_pipe[0], F_GETFL, 0);
    if (pipe_flags < 0 || fcntl(serial_pipe[0], F_SETFL, pipe_flags | O_NONBLOCK) != 0) {
      close(serial_pipe[0]);
      close(serial_pipe[1]);
      close(serial_input_pipe[0]);
      close(serial_input_pipe[1]);
      fputs("Could not bound the guest-serial reader\n", stderr);
      return 6;
    }
    NSFileHandle *serial_write_handle =
        [[NSFileHandle alloc] initWithFileDescriptor:serial_pipe[1] closeOnDealloc:YES];
    NSFileHandle *serial_input_read_handle =
        [[NSFileHandle alloc] initWithFileDescriptor:serial_input_pipe[0] closeOnDealloc:YES];
    NSFileHandle *serial_input_write_handle =
        [[NSFileHandle alloc] initWithFileDescriptor:serial_input_pipe[1] closeOnDealloc:YES];
    NSMutableData *serial_output = [NSMutableData data];

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
      close(serial_pipe[0]);
      return EmitRecord(record) == 0 ? 7 : 1;
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
      close(serial_pipe[0]);
      return EmitRecord(record) == 0 ? 7 : 1;
    }

    VZUSBMassStorageDeviceConfiguration *iso_device =
        [[VZUSBMassStorageDeviceConfiguration alloc] initWithAttachment:attachment];
    VZXHCIControllerConfiguration *usb_controller = [[VZXHCIControllerConfiguration alloc] init];
    usb_controller.usbDevices = @[ iso_device ];

    VZEFIBootLoader *boot_loader = [[VZEFIBootLoader alloc] init];
    boot_loader.variableStore = variable_store;
    VZVirtioConsoleDeviceSerialPortConfiguration *serial_port =
        [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    serial_port.attachment = [[VZFileHandleSerialPortAttachment alloc]
        initWithFileHandleForReading:serial_input_read_handle fileHandleForWriting:serial_write_handle];

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = 2;
    configuration.memorySize = 1024ULL * 1024ULL * 1024ULL;
    configuration.usbControllers = @[ usb_controller ];
    configuration.serialPorts = @[ serial_port ];
    configuration.networkDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.socketDevices = @[];
    configuration.storageDevices = @[];

    NSError *validation_error = nil;
    if (![configuration validateWithError:&validation_error]) {
      NSDictionary *record = @{
        @"configuration_valid": @NO,
        @"validation_error": validation_error.localizedDescription ?: @"configuration validation failed",
        @"vm_object_created": @NO,
        @"vm_boot_attempted": @NO
      };
      close(serial_pipe[0]);
      return EmitRecord(record) == 0 ? 8 : 1;
    }

    dispatch_queue_t vm_queue = dispatch_queue_create("com.mac-operator.virtualization-efi-iso-serial-probe", DISPATCH_QUEUE_SERIAL);
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
    if (start_succeeded) CaptureSerialFor(serial_pipe[0], serial_output, 18.0);
    BOOL guest_diagnostics_sent = NO;
    BOOL guest_root_login_attempted = NO;
    BOOL guest_root_shell_marker = NO;
    BOOL guest_root_identity_marker = NO;
    BOOL guest_canary_command_sent = NO;
    BOOL guest_canary_armed_marker = NO;
    BOOL guest_canary_alive_marker = NO;
    if (start_succeeded && ContainsBytes(serial_output, "Launching initramfs emergency recovery shell.") &&
        ContainsBytes(serial_output, "~ #")) {
      NSData *diagnostic_command = [@"echo MOP_PROBE_BEGIN; mkdir -p /tmp/probe-media; mount -t iso9660 -o ro /dev/sda /tmp/probe-media; ls -la /tmp/probe-media; ls -la /tmp/probe-media/apks; test -e /tmp/probe-media/apks/.boot_repository; echo marker_status=$?; mount; echo MOP_PROBE_END\r"
          dataUsingEncoding:NSUTF8StringEncoding];
      [serial_input_write_handle writeData:diagnostic_command];
      guest_diagnostics_sent = YES;
      CaptureSerialFor(serial_pipe[0], serial_output, 2.0);
    }
    if (start_succeeded && ContainsBytes(serial_output, "localhost login:")) {
      NSData *root_login = [@"root\r\r" dataUsingEncoding:NSUTF8StringEncoding];
      [serial_input_write_handle writeData:root_login];
      guest_root_login_attempted = YES;
      CaptureSerialFor(serial_pipe[0], serial_output, 2.0);
      guest_root_shell_marker = ContainsBytes(serial_output, "localhost:~#") ||
          ContainsBytes(serial_output, "~ #");
      if (guest_root_shell_marker) {
        NSData *identity_command = [@"id; echo MOP_ROOT_SESSION_CONFIRMED\r"
            dataUsingEncoding:NSUTF8StringEncoding];
        [serial_input_write_handle writeData:identity_command];
        CaptureSerialFor(serial_pipe[0], serial_output, 1.0);
        guest_root_identity_marker = ContainsBytes(serial_output, "uid=0(root)") &&
            ContainsBytes(serial_output, "MOP_ROOT_SESSION_CONFIRMED");
        if (guest_root_identity_marker) {
          NSData *canary_command = [@"sh -c 'if command -v setsid >/dev/null 2>&1; then sh -c \"setsid sh -c \\\"sleep 2; echo MOP_GUEST_CANARY_ALIVE > /dev/hvc0; sleep 8; echo MOP_GUEST_CANARY_LATE > /dev/hvc0\\\" </dev/null >/dev/null 2>&1 &\" </dev/null >/dev/null 2>&1 & echo MOP_GUEST_CANARY_ARMED; else echo MOP_GUEST_CANARY_SETID_UNAVAILABLE; fi'\r"
              dataUsingEncoding:NSUTF8StringEncoding];
          [serial_input_write_handle writeData:canary_command];
          guest_canary_command_sent = YES;
          CaptureSerialFor(serial_pipe[0], serial_output, 4.0);
          guest_canary_armed_marker = ContainsBytes(serial_output, "MOP_GUEST_CANARY_ARMED");
          guest_canary_alive_marker = ContainsBytes(serial_output, "MOP_GUEST_CANARY_ALIVE");
        }
      }
    }
    const BOOL guest_canary_late_marker_seen_before_stop =
        ContainsBytes(serial_output, "MOP_GUEST_CANARY_LATE");

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
          state_after_stop = @"stopped";
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
          const VZVirtualMachineState final_state = machine.state;
          state_after_stop = StateName(final_state);
          state_stopped = final_state == VZVirtualMachineStateStopped;
          dispatch_semaphore_signal(stop_semaphore);
        }];
      });
    }
    const BOOL stop_completed = start_succeeded && WaitFor(stop_semaphore, 45.0);
    const BOOL stopped_readback = stop_completed && state_stopped;
    const NSUInteger bytes_before_post_stop = serial_output.length;
    CaptureSerialFor(serial_pipe[0], serial_output, 12.0);
    const NSUInteger post_stop_serial_bytes = serial_output.length - bytes_before_post_stop;
    NSData *post_stop_data = [serial_output subdataWithRange:
        NSMakeRange(bytes_before_post_stop, post_stop_serial_bytes)];
    NSString *post_stop_text = [[NSString alloc] initWithData:post_stop_data
        encoding:NSUTF8StringEncoding] ?: @"";
    const BOOL guest_canary_late_marker_after_stop =
        [post_stop_text containsString:@"MOP_GUEST_CANARY_LATE"];

    NSString *serial_text = [[NSString alloc] initWithData:serial_output encoding:NSUTF8StringEncoding];
    if (serial_text == nil) serial_text = [serial_output base64EncodedStringWithOptions:0];
    const BOOL linux_marker = ContainsBytes(serial_output, "Linux version ") ||
        ContainsBytes(serial_output, "Run /init as init process");
    NSString *lowercase_text = serial_text.lowercaseString;
    const BOOL alpine_initramfs_marker = [serial_text containsString:@"Alpine Init"];
    const BOOL alpine_marker = [lowercase_text containsString:@"welcome to alpine"] ||
        [lowercase_text containsString:@"localhost login:"];
    const BOOL boot_media_mounted = [serial_text containsString:@"Mounting boot media: ok."];
    const BOOL boot_repository_marker_found = [serial_text containsString:@"marker_status=0"];
    const BOOL recovery_shell_marker =
        [serial_text containsString:@"Launching initramfs emergency recovery shell."];

    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"virtualization_supported": @YES,
      @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
      @"boot_loader": @"VZEFIBootLoader",
      @"boot_media": @"read-only USB mass-storage ISO with pinned hvc0 GRUB configuration",
      @"iso_sha256": [NSString stringWithUTF8String:iso_sha256],
      @"iso_bytes": @(iso_bytes),
      @"iso_attachment_read_only": @(attachment.readOnly),
      @"configuration_valid": @YES,
      @"cpu_count": @2,
      @"memory_bytes": @(configuration.memorySize),
      @"network_devices": @0,
      @"directory_sharing_devices": @0,
      @"socket_devices": @0,
      @"serial_ports": @1,
      @"vm_object_created": @YES,
      @"vm_boot_attempted": @YES,
      @"start_completed": @(start_completed),
      @"start_succeeded": @(start_succeeded),
      @"state_after_start": state_after_start,
      @"start_error": start_error.localizedDescription ?: @"",
      @"start_error_domain": start_error.domain ?: @"",
      @"start_error_code": start_error == nil ? @0 : @(start_error.code),
      @"serial_bytes": @(serial_output.length),
      @"guest_read_only_diagnostics_sent": @(guest_diagnostics_sent),
      @"guest_root_login_attempted": @(guest_root_login_attempted),
      @"guest_root_shell_marker": @(guest_root_shell_marker),
      @"guest_root_identity_marker": @(guest_root_identity_marker),
      @"guest_canary_command_sent": @(guest_canary_command_sent),
      @"guest_canary_armed_marker": @(guest_canary_armed_marker),
      @"guest_canary_alive_marker": @(guest_canary_alive_marker),
      @"guest_canary_late_marker_seen_before_stop": @(guest_canary_late_marker_seen_before_stop),
      @"guest_canary_late_marker_after_stop": @(guest_canary_late_marker_after_stop),
      @"linux_kernel_marker": @(linux_marker),
      @"alpine_initramfs_marker": @(alpine_initramfs_marker),
      @"alpine_userspace_marker": @(alpine_marker),
      @"boot_media_mounted_marker": @(boot_media_mounted),
      @"boot_repository_marker_found_by_guest_probe": @(boot_repository_marker_found),
      @"recovery_shell_marker": @(recovery_shell_marker),
      @"serial_text": serial_text ?: @"",
      @"state_before_stop": state_before_stop,
      @"hard_stop_attempted": @(stop_attempted),
      @"hard_stop_possible": @(stop_possible),
      @"hard_stop_completed": @(stop_completed && stop_attempted && stop_error == nil),
      @"stop_error": stop_error.localizedDescription ?: @"",
      @"state_after_stop": state_after_stop,
      @"stopped_state_readback": @(stopped_readback),
      @"post_stop_serial_bytes": @(post_stop_serial_bytes)
    };
    const int output_status = EmitRecord(record);
    close(serial_pipe[0]);
    const BOOL success = start_succeeded && linux_marker && alpine_initramfs_marker &&
        guest_root_identity_marker && guest_canary_command_sent && guest_canary_armed_marker &&
        guest_canary_alive_marker && !guest_canary_late_marker_seen_before_stop &&
        !guest_canary_late_marker_after_stop && stop_completed && stop_error == nil && stopped_readback;
    return output_status != 0 ? output_status : (success ? 0 : 9);
  }
}
