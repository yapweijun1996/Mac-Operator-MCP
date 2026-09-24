#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const off_t kExpectedDiskBytes = 64LL * 1024LL * 1024LL;

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

static int EmitRecord(NSDictionary *record) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:&error];
  if (data == nil) {
    fputs("Virtualization EFI baseline probe could not encode its result\n", stderr);
    return 1;
  }
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 3) {
      fputs("Usage: virtualization_efi_baseline_probe <empty-raw-disk> <new-variable-store>\n", stderr);
      return 2;
    }
    if (!HasVirtualizationEntitlement()) {
      fputs("Virtualization entitlement is absent from the probe process\n", stderr);
      return 3;
    }

    const int disk_descriptor = open(argv[1], O_RDONLY | O_NOFOLLOW);
    if (disk_descriptor < 0) {
      fputs("Could not open the baseline disk without following symlinks\n", stderr);
      return 4;
    }
    struct stat disk_metadata;
    const BOOL disk_is_valid = fstat(disk_descriptor, &disk_metadata) == 0 &&
        S_ISREG(disk_metadata.st_mode) && disk_metadata.st_size == kExpectedDiskBytes;
    close(disk_descriptor);
    if (!disk_is_valid) {
      fputs("Baseline disk must be a regular 64 MiB raw file\n", stderr);
      return 4;
    }

    NSString *disk_path = [NSString stringWithUTF8String:argv[1]];
    if (disk_path == nil || ![VZVirtualMachine isSupported]) {
      fputs("Virtualization host or baseline disk path is unavailable\n", stderr);
      return 5;
    }

    NSError *attachment_error = nil;
    VZDiskImageStorageDeviceAttachment *attachment =
        [[VZDiskImageStorageDeviceAttachment alloc]
            initWithURL:[NSURL fileURLWithPath:disk_path]
            readOnly:YES
            error:&attachment_error];
    if (attachment == nil) {
      NSDictionary *record = @{
        @"configuration_valid": @NO,
        @"attachment_error": attachment_error.localizedDescription ?: @"disk attachment failed",
        @"vm_object_created": @NO,
        @"vm_boot_attempted": @NO
      };
      return EmitRecord(record) == 0 ? 6 : 1;
    }

    NSString *variable_store_path = [NSString stringWithUTF8String:argv[2]];
    if (variable_store_path == nil) {
      fputs("EFI variable-store path is invalid\n", stderr);
      return 6;
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

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    VZEFIBootLoader *boot_loader = [[VZEFIBootLoader alloc] init];
    boot_loader.variableStore = variable_store;
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = VZVirtualMachineConfiguration.minimumAllowedCPUCount;
    configuration.memorySize = VZVirtualMachineConfiguration.minimumAllowedMemorySize;
    configuration.storageDevices = @[
      [[VZVirtioBlockDeviceConfiguration alloc] initWithAttachment:attachment]
    ];
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

    dispatch_queue_t vm_queue = dispatch_queue_create("com.mac-operator.virtualization-efi-baseline-probe", DISPATCH_QUEUE_SERIAL);
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
    const BOOL start_completed = WaitFor(start_semaphore, 30.0);
    const BOOL start_succeeded = start_completed && start_error == nil && start_state_running;

    dispatch_semaphore_t stop_semaphore = dispatch_semaphore_create(0);
    __block NSError *stop_error = nil;
    __block BOOL stop_attempted = NO;
    __block BOOL stop_possible = NO;
    __block BOOL state_stopped = NO;
    __block NSString *state_after_stop = @"not_attempted";
    if (start_succeeded) {
      dispatch_async(vm_queue, ^{
        const VZVirtualMachineState state = machine.state;
        state_after_stop = StateName(state);
        if (state == VZVirtualMachineStateStopped) {
          state_stopped = YES;
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
    const BOOL stop_completed = start_succeeded && WaitFor(stop_semaphore, 30.0);
    const BOOL stopped_readback = stop_completed && state_stopped;

    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"virtualization_supported": @YES,
      @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
      @"boot_loader": @"VZEFIBootLoader",
      @"configuration_valid": @YES,
      @"disk_bytes": @(disk_metadata.st_size),
      @"disk_read_only": @YES,
      @"variable_store_created": @YES,
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
