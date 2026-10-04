#import <AppKit/AppKit.h>

// Read-only LaunchServices lookup for the unique temporary test bundle.
int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 3) return 64;
    NSString *bundleId = [NSString stringWithUTF8String:argv[1]];
    NSString *expectedPath = [NSString stringWithUTF8String:argv[2]];
    NSURL *resolved = [NSWorkspace.sharedWorkspace URLForApplicationWithBundleIdentifier:bundleId];
    NSString *normalizedExpected = expectedPath.stringByStandardizingPath.stringByResolvingSymlinksInPath;
    NSString *normalizedResolved = resolved.path.stringByStandardizingPath.stringByResolvingSymlinksInPath;
    NSDictionary *result = @{ @"bundle_resolved": @((BOOL)(resolved != nil)),
      @"path_matches_expected": @((BOOL)(resolved != nil && [normalizedResolved isEqualToString:normalizedExpected])),
      @"expected_bundle_matches": @((BOOL)([[NSBundle bundleWithPath:expectedPath].bundleIdentifier isEqualToString:bundleId])) };
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
    fwrite(data.bytes, 1, data.length, stdout);
    return 0;
  }
}
