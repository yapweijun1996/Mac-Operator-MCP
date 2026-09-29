#import <AppKit/AppKit.h>
#import <Security/Security.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>

static volatile sig_atomic_t stopped = 0;
static void stopLauncher(int signalNumber) { (void)signalNumber; stopped = 1; }
static void tick(void) { [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]]; }

int main(void) {
  @autoreleasepool {
    signal(SIGTERM, stopLauncher);
    signal(SIGINT, stopLauncher);
    signal(SIGPIPE, SIG_IGN);
    // Fixed app identity; no caller-supplied application URL or executable.
    struct passwd *owner = getpwuid(getuid());
    if (owner == NULL) return 70;
    NSString *appPath = [[NSString stringWithUTF8String:owner->pw_dir] stringByAppendingPathComponent:@"Applications/Mac Operator GUI.app"];
    NSURL *appURL = [NSURL fileURLWithPath:appPath];
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    OSStatus identity = SecRequirementCreateWithString(CFSTR("identifier \"dev.macoperator.personal.gui\""), kSecCSDefaultFlags, &requirement);
    if (identity == errSecSuccess) identity = SecStaticCodeCreateWithPath((__bridge CFURLRef)appURL, kSecCSDefaultFlags, &code);
    if (identity == errSecSuccess) identity = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement);
    if (code != NULL) CFRelease(code);
    if (requirement != NULL) CFRelease(requirement);
    if (identity != errSecSuccess) return 71;
    NSMutableData *request = [NSMutableData data];
    char input[4096]; size_t count;
    while ((count = fread(input, 1, sizeof(input), stdin)) > 0) {
      [request appendBytes:input length:count];
      if (request.length > 65536) return 72;
    }
    if (ferror(stdin) || request.length == 0 || stopped) return 72;
    char directory[] = "/tmp/mop-gui-XXXXXX";
    if (mkdtemp(directory) == NULL) return 73;
    NSString *socketPath = [[NSString stringWithUTF8String:directory] stringByAppendingPathComponent:@"control"];
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strlcpy(address.sun_path, socketPath.fileSystemRepresentation, sizeof(address.sun_path));
    int peer = -1;
    __block NSRunningApplication *application = nil;
    __block BOOL launchCompleted = NO;
    int status = 74;
    NSMutableData *output = [NSMutableData data];
    double deadline = NSProcessInfo.processInfo.systemUptime + 12;
    if (listener >= 0 && bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 &&
        listen(listener, 1) == 0 && fcntl(listener, F_SETFL, O_NONBLOCK) == 0) {
      NSWorkspaceOpenConfiguration *configuration = NSWorkspaceOpenConfiguration.configuration;
      configuration.createsNewApplicationInstance = YES;
      configuration.allowsRunningApplicationSubstitution = NO;
      configuration.activates = NO;
      configuration.addsToRecentItems = NO;
      configuration.promptsUserIfNeeded = NO;
      configuration.arguments = @[@"--broker-socket", socketPath];
      [NSWorkspace.sharedWorkspace openApplicationAtURL:appURL configuration:configuration completionHandler:^(NSRunningApplication *app, NSError *error) {
        (void)error;
        dispatch_async(dispatch_get_main_queue(), ^{
          application = app;
          launchCompleted = YES;
        });
      }];
      while (!stopped && NSProcessInfo.processInfo.systemUptime < deadline && !launchCompleted) tick();
      while (!stopped && application != nil && NSProcessInfo.processInfo.systemUptime < deadline && peer < 0) {
        peer = accept(listener, NULL, NULL);
        if (peer < 0) tick();
      }
      pid_t peerPid = -1; socklen_t pidLength = sizeof(peerPid);
      uid_t uid = (uid_t)-1; gid_t gid;
      NSString *executable = [appPath stringByAppendingPathComponent:@"Contents/MacOS/gui_vision"];
      if (!stopped && peer >= 0 && getpeereid(peer, &uid, &gid) == 0 && uid == getuid() &&
          getsockopt(peer, SOL_LOCAL, LOCAL_PEERPID, &peerPid, &pidLength) == 0 &&
          peerPid == application.processIdentifier && [application.executableURL.path isEqualToString:executable] &&
          [application.bundleIdentifier isEqualToString:@"dev.macoperator.personal.gui"]) {
        fcntl(peer, F_SETFL, O_NONBLOCK);
        uint32_t size = htonl((uint32_t)request.length);
        NSMutableData *frame = [NSMutableData dataWithBytes:&size length:sizeof(size)];
        [frame appendData:request];
        NSUInteger sent = 0;
        BOOL failed = NO;
        while (!stopped && sent < frame.length && NSProcessInfo.processInfo.systemUptime < deadline) {
          ssize_t written = write(peer, (const char *)frame.bytes + sent, frame.length - sent);
          if (written > 0) sent += (NSUInteger)written;
          else if (errno != EAGAIN && errno != EINTR) { failed = YES; break; }
          else tick();
        }
        BOOL eof = NO;
        while (!stopped && !failed && sent == frame.length && !eof && NSProcessInfo.processInfo.systemUptime < deadline) {
          char bytes[8192]; ssize_t received = read(peer, bytes, sizeof(bytes));
          if (received > 0) {
            [output appendBytes:bytes length:(NSUInteger)received];
            if (output.length > 1048576) failed = YES;
          } else if (received == 0) eof = YES;
          else if (errno != EAGAIN && errno != EINTR) failed = YES;
          else tick();
        }
        while (!stopped && eof && !application.terminated && NSProcessInfo.processInfo.systemUptime < deadline) tick();
        if (!stopped && !failed && eof && application.terminated && output.length > 0) status = 0;
      }
    }
    if (peer >= 0) close(peer);
    if (listener >= 0) close(listener);
    unlink(socketPath.fileSystemRepresentation);
    rmdir(directory);
    if (application != nil && !application.terminated) {
      [application forceTerminate];
      double cleanupDeadline = NSProcessInfo.processInfo.systemUptime + 0.15;
      while (!application.terminated && NSProcessInfo.processInfo.systemUptime < cleanupDeadline) tick();
      status = 75;
    }
    if (status == 0) {
      if (fwrite(output.bytes, 1, output.length, stdout) != output.length) return 76;
    }
    return status;
  }
}
