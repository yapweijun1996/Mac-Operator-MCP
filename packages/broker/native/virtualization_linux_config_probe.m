#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#include <sys/stat.h>

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

static BOOL ReadRegularFile(const char *path, unsigned long long *size) {
  struct stat metadata;
  if (path == NULL || lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 1) return NO;
  *size = (unsigned long long)metadata.st_size;
  return YES;
}

static int EmitRecord(NSDictionary *record) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:&error];
  if (data == nil) {
    fputs("Virtualization Linux configuration probe could not encode its result\n", stderr);
    return 1;
  }
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    if (argc != 3) {
      fputs("Usage: virtualization_linux_config_probe <kernel> <initramfs>\n", stderr);
      return 2;
    }
    if (!HasVirtualizationEntitlement()) {
      fputs("Virtualization entitlement is absent from the probe process\n", stderr);
      return 3;
    }

    unsigned long long kernel_size = 0;
    unsigned long long initramfs_size = 0;
    if (!ReadRegularFile(argv[1], &kernel_size) || !ReadRegularFile(argv[2], &initramfs_size)) {
      fputs("Kernel and initramfs must be non-empty regular files\n", stderr);
      return 4;
    }

    NSString *kernel_path = [NSString stringWithUTF8String:argv[1]];
    NSString *initramfs_path = [NSString stringWithUTF8String:argv[2]];
    if (kernel_path == nil || initramfs_path == nil) {
      fputs("Kernel or initramfs path is not valid UTF-8\n", stderr);
      return 4;
    }

    VZLinuxBootLoader *boot_loader = [[VZLinuxBootLoader alloc]
        initWithKernelURL:[NSURL fileURLWithPath:kernel_path]];
    boot_loader.initialRamdiskURL = [NSURL fileURLWithPath:initramfs_path];
    boot_loader.commandLine = @"console=hvc0 rdinit=/init";

    VZVirtioConsoleDeviceSerialPortConfiguration *console =
        [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    console.attachment = [[VZFileHandleSerialPortAttachment alloc]
        initWithFileHandleForReading:nil
        fileHandleForWriting:[NSFileHandle fileHandleWithStandardOutput]];

    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = boot_loader;
    configuration.CPUCount = VZVirtualMachineConfiguration.minimumAllowedCPUCount;
    configuration.memorySize = VZVirtualMachineConfiguration.minimumAllowedMemorySize;
    configuration.serialPorts = @[ console ];
    configuration.audioDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.networkDevices = @[];
    configuration.socketDevices = @[];
    configuration.storageDevices = @[];

    NSError *validation_error = nil;
    const BOOL valid = [configuration validateWithError:&validation_error];
    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"virtualization_supported": @([VZVirtualMachine isSupported]),
      @"virtualization_entitlement": @(HasVirtualizationEntitlement()),
      @"boot_loader": @"VZLinuxBootLoader",
      @"kernel_bytes": @(kernel_size),
      @"initramfs_bytes": @(initramfs_size),
      @"configuration_valid": @(valid),
      @"network_devices": @0,
      @"directory_sharing_devices": @0,
      @"storage_devices": @0,
      @"vm_object_created": @NO,
      @"vm_boot_attempted": @NO,
      @"validation_error": validation_error.localizedDescription ?: @""
    };
    const int output_status = EmitRecord(record);
    return output_status != 0 ? output_status : (valid ? 0 : 1);
  }
}
