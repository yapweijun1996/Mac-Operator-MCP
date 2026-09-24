#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef MOP_USE_DEFAULT_VM_QUEUE
#define MOP_USE_DEFAULT_VM_QUEUE 0
#endif

static const char *kExpectedKernelSha256 =
    "e45e1f6083d1ed45db6647b422e32b6ae6dc54de7b8190b7b97744fb293412e3";
static const char *kExpectedInitramfsSha256 =
    "ffe65ec5a0c0bf470042ad28f7ce7aa5f842ce8090e4230fb2703a7a34e1bebe";
static const char *kFedoraKernelSha256 =
    "e55a5f9a9177267f58d1e957f58e6b294a4552cfe7cdf72174e686edd6b474da";
static const char *kFedoraInitramfsSha256 =
    "19bf3a8ca66478e86940386ab480e428f0cf0aa6028eb118137a01830b685eff";
static const size_t kMaximumSerialBytes = 16 * 1024;

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
#if MOP_USE_DEFAULT_VM_QUEUE
  const double deadline = MonotonicSeconds() + timeout_seconds;
  for (;;) {
    if (dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) == 0) return YES;
    if (MonotonicSeconds() >= deadline) return NO;
    [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode
        beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
  }
#else
  const int64_t nanoseconds = (int64_t)(timeout_seconds * (double)NSEC_PER_SEC);
  return dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
#endif
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
    fputs("Virtualization Linux boot probe could not encode its result\n", stderr);
    return 1;
  }
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 3) {
      fputs("Usage: virtualization_linux_boot_probe <pinned-kernel> <pinned-initramfs>\n", stderr);
      return 2;
    }
    if (!HasVirtualizationEntitlement()) {
      fputs("Virtualization entitlement is absent from the probe process\n", stderr);
      return 3;
    }

    char kernel_sha256[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    char initramfs_sha256[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned long long kernel_size = 0;
    unsigned long long initramfs_size = 0;
    const BOOL kernel_only = strcmp(argv[2], "-") == 0;
    if (!HashRegularFile(argv[1], kernel_sha256, &kernel_size) ||
        (!kernel_only && !HashRegularFile(argv[2], initramfs_sha256, &initramfs_size))) {
      fputs("Kernel or initramfs could not be safely hashed\n", stderr);
      return 4;
    }
    if (kernel_only) initramfs_sha256[0] = '\0';
    const BOOL alpine_kernel = strcmp(kernel_sha256, kExpectedKernelSha256) == 0;
    const BOOL fedora_kernel = strcmp(kernel_sha256, kFedoraKernelSha256) == 0;
    const BOOL alpine_assets = alpine_kernel &&
        (kernel_only || strcmp(initramfs_sha256, kExpectedInitramfsSha256) == 0);
    const BOOL fedora_assets = fedora_kernel &&
        (kernel_only || strcmp(initramfs_sha256, kFedoraInitramfsSha256) == 0);
    if (!alpine_assets && !fedora_assets) {
      fputs("Kernel and initramfs did not match a pinned Alpine 3.24.2 or Fedora 44 ARM64 pair\n", stderr);
      return 4;
    }

    NSString *kernel_path = [NSString stringWithUTF8String:argv[1]];
    NSString *initramfs_path = kernel_only ? nil : [NSString stringWithUTF8String:argv[2]];
    if (kernel_path == nil || (!kernel_only && initramfs_path == nil) || ![VZVirtualMachine isSupported]) {
      fputs("Virtualization host or image path is unavailable\n", stderr);
      return 5;
    }

    int serial_pipe[2];
    if (pipe(serial_pipe) != 0) {
      fputs("Could not create the bounded serial-output pipe\n", stderr);
      return 6;
    }
    const int flags = fcntl(serial_pipe[0], F_GETFL, 0);
    if (flags < 0 || fcntl(serial_pipe[0], F_SETFL, flags | O_NONBLOCK) != 0) {
      close(serial_pipe[0]);
      close(serial_pipe[1]);
      fputs("Could not bound the serial-output reader\n", stderr);
      return 6;
    }
    NSFileHandle *serial_read_handle = [[NSFileHandle alloc] initWithFileDescriptor:serial_pipe[0] closeOnDealloc:YES];
    NSFileHandle *serial_write_handle = [[NSFileHandle alloc] initWithFileDescriptor:serial_pipe[1] closeOnDealloc:YES];

    VZLinuxBootLoader *boot_loader = [[VZLinuxBootLoader alloc]
        initWithKernelURL:[NSURL fileURLWithPath:kernel_path]];
    if (!kernel_only) boot_loader.initialRamdiskURL = [NSURL fileURLWithPath:initramfs_path];
    boot_loader.commandLine = @"console=hvc0";

    VZVirtioConsoleDeviceSerialPortConfiguration *console =
        [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    console.attachment = [[VZFileHandleSerialPortAttachment alloc]
        initWithFileHandleForReading:nil fileHandleForWriting:serial_write_handle];

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = 2;
    configuration.memorySize = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    configuration.serialPorts = @[ console ];
    configuration.audioDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.networkDevices = @[];
    configuration.socketDevices = @[];
    configuration.entropyDevices = @[
      [[VZVirtioEntropyDeviceConfiguration alloc] init]
    ];
    configuration.storageDevices = @[];

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

#if MOP_USE_DEFAULT_VM_QUEUE
    VZVirtualMachine *machine = [[VZVirtualMachine alloc] initWithConfiguration:configuration];
#else
    dispatch_queue_t vm_queue = dispatch_queue_create("com.mac-operator.virtualization-linux-probe", DISPATCH_QUEUE_SERIAL);
    VZVirtualMachine *machine = [[VZVirtualMachine alloc] initWithConfiguration:configuration queue:vm_queue];
#endif
    NSMutableData *serial_output = [NSMutableData data];

    dispatch_semaphore_t start_semaphore = dispatch_semaphore_create(0);
    __block NSError *start_error = nil;
    __block BOOL start_state_running = NO;
    __block NSString *start_state_name = @"unknown";
    dispatch_block_t start_operation = ^{
      [machine startWithCompletionHandler:^(NSError *error) {
        start_error = error;
        const VZVirtualMachineState state = machine.state;
        start_state_name = StateName(state);
        start_state_running = state == VZVirtualMachineStateRunning;
        dispatch_semaphore_signal(start_semaphore);
      }];
    };
#if MOP_USE_DEFAULT_VM_QUEUE
    start_operation();
#else
    dispatch_async(vm_queue, start_operation);
#endif
    const BOOL start_completed = WaitFor(start_semaphore, 30.0);
    const BOOL start_succeeded = start_completed && start_error == nil && start_state_running;

    if (start_succeeded) CaptureSerialFor(serial_pipe[0], serial_output, 8.0);

    dispatch_semaphore_t stop_semaphore = dispatch_semaphore_create(0);
    __block NSError *stop_error = nil;
    __block BOOL stop_state_stopped = NO;
    __block BOOL stop_attempted = NO;
    __block BOOL stop_can_stop = NO;
    __block NSString *state_after_stop = @"unknown";
    dispatch_block_t stop_operation = ^{
      VZVirtualMachineState state = machine.state;
      state_after_stop = StateName(state);
      if (state == VZVirtualMachineStateStopped) {
        stop_state_stopped = YES;
        dispatch_semaphore_signal(stop_semaphore);
        return;
      }
      stop_can_stop = machine.canStop;
      if (!stop_can_stop) {
        dispatch_semaphore_signal(stop_semaphore);
        return;
      }
      stop_attempted = YES;
      [machine stopWithCompletionHandler:^(NSError *error) {
        stop_error = error;
        const VZVirtualMachineState completed_state = machine.state;
        state_after_stop = StateName(completed_state);
        stop_state_stopped = completed_state == VZVirtualMachineStateStopped;
        dispatch_semaphore_signal(stop_semaphore);
      }];
    };
#if MOP_USE_DEFAULT_VM_QUEUE
    stop_operation();
#else
    dispatch_async(vm_queue, stop_operation);
#endif
    const BOOL stop_completed = WaitFor(stop_semaphore, 30.0);
    const BOOL stopped_readback = stop_completed && stop_state_stopped;

    const NSUInteger bytes_at_stop = serial_output.length;
    CaptureSerialFor(serial_pipe[0], serial_output, 1.0);
    const NSUInteger post_stop_serial_bytes = serial_output.length - bytes_at_stop;
    const BOOL kernel_boot_marker = ContainsBytes(serial_output, "Linux version ");
    NSString *serial_text = [[NSString alloc] initWithData:serial_output encoding:NSUTF8StringEncoding];
    if (serial_text == nil) serial_text = [serial_output base64EncodedStringWithOptions:0];

    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"virtualization_supported": @YES,
      @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
      @"boot_loader": @"VZLinuxBootLoader",
      @"vm_queue_strategy": MOP_USE_DEFAULT_VM_QUEUE ? @"framework-default" : @"project-serial-queue",
      @"boot_environment": fedora_assets ? @"Fedora 44 aarch64 pxeboot" : @"Alpine 3.24.2 aarch64 netboot",
      @"kernel_sha256": [NSString stringWithUTF8String:kernel_sha256],
      @"initramfs_sha256": kernel_only ? @"not-provided" : [NSString stringWithUTF8String:initramfs_sha256],
      @"kernel_bytes": @(kernel_size),
      @"initramfs_provided": @(!kernel_only),
      @"initramfs_bytes": @(initramfs_size),
      @"configuration_valid": @YES,
      @"network_devices": @0,
      @"directory_sharing_devices": @0,
      @"storage_devices": @0,
      @"entropy_devices": @1,
      @"vm_object_created": @YES,
      @"vm_boot_attempted": @YES,
      @"start_completed": @(start_completed),
      @"start_succeeded": @(start_succeeded),
      @"state_after_start": start_state_name,
      @"start_error": start_error.localizedDescription ?: @"",
      @"start_error_domain": start_error.domain ?: @"",
      @"start_error_code": start_error == nil ? @0 : @(start_error.code),
      @"start_error_failure_reason": [start_error.userInfo[NSLocalizedFailureReasonErrorKey] isKindOfClass:[NSString class]]
          ? start_error.userInfo[NSLocalizedFailureReasonErrorKey] : @"",
      @"start_error_debug_description": [start_error.userInfo[@"NSDebugDescription"] isKindOfClass:[NSString class]]
          ? start_error.userInfo[@"NSDebugDescription"] : @"",
      @"hard_stop_attempted": @(stop_attempted),
      @"hard_stop_possible": @(stop_can_stop),
      @"hard_stop_completed": @(stop_completed && stop_attempted && stop_error == nil),
      @"stop_error": stop_error.localizedDescription ?: @"",
      @"state_after_stop": state_after_stop,
      @"stopped_state_readback": @(stopped_readback),
      @"kernel_boot_marker": @(kernel_boot_marker),
      @"serial_bytes": @(serial_output.length),
      @"post_stop_serial_bytes": @(post_stop_serial_bytes),
      @"serial_output": serial_text
    };

    [serial_read_handle closeFile];
    [serial_write_handle closeFile];
    const int output_status = EmitRecord(record);
    const BOOL success = start_succeeded && kernel_boot_marker && stop_completed &&
        stop_error == nil && stopped_readback;
    return output_status != 0 ? output_status : (success ? 0 : 8);
  }
}
