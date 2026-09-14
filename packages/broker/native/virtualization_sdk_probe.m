#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

int main(void) {
  @autoreleasepool {
    VZVirtualMachineConfiguration *configuration = [[VZVirtualMachineConfiguration alloc] init];
    NSError *validationError = nil;
    BOOL configurationValid = [configuration validateWithError:&validationError];
    NSDictionary *record = @{
      @"framework": @"Virtualization.framework",
      @"host_version": [[NSProcessInfo processInfo] operatingSystemVersionString],
      @"configuration_type": NSStringFromClass([configuration class]),
      @"virtualization_supported": @([VZVirtualMachine isSupported]),
      @"configuration_valid_without_guest": @(configurationValid),
      @"validation_error_present": @(validationError != nil),
      @"vm_boot_attempted": @NO
    };
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:&error];
    if (data == nil) {
      fputs("virtualization probe output failed\n", stderr);
      return 1;
    }
    fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
  }
  return 0;
}
