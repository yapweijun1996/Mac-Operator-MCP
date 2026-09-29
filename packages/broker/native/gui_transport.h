#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>

static BOOL transferBytes(int fd, void *bytes, size_t length, BOOL writing) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = writing ? write(fd, (char *)bytes + offset, length - offset)
                            : read(fd, (char *)bytes + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return NO;
    offset += (size_t)count;
  }
  return YES;
}

static void configureSocket(int fd) {
  int enabled = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
  struct timeval timeout = { 2, 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static BOOL sameOwner(int fd) {
  uid_t uid; gid_t gid;
  return getpeereid(fd, &uid, &gid) == 0 && uid == getuid();
}

// The app refuses to operate until a bounded request arrives from its launcher.
// Closing the connection cancels the app even if its GUI call is blocked.
static NSDictionary *receiveGuiRequest(NSString *path) {
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  if (path.length == 0 || strlen(path.fileSystemRepresentation) >= sizeof(address.sun_path)) return nil;
  strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof(address.sun_path));
  struct stat parent;
  if (lstat(path.stringByDeletingLastPathComponent.fileSystemRepresentation, &parent) != 0 ||
      !S_ISDIR(parent.st_mode) || parent.st_uid != getuid() || (parent.st_mode & 077) != 0) return nil;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return nil;
  configureSocket(fd);
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || !sameOwner(fd)) { close(fd); return nil; }
  uint32_t length;
  if (!transferBytes(fd, &length, sizeof(length), NO) || ntohl(length) > 65536 || ntohl(length) == 0) { close(fd); return nil; }
  NSMutableData *data = [NSMutableData dataWithLength:ntohl(length)];
  if (!transferBytes(fd, data.mutableBytes, data.length, NO)) { close(fd); return nil; }
  id request = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  if (![request isKindOfClass:NSDictionary.class] || ![request[@"args"] isKindOfClass:NSArray.class] ||
      ![request[@"stdin"] isKindOfClass:NSString.class] || [request[@"args"] count] > 32) { close(fd); return nil; }
  for (id argument in request[@"args"]) {
    if (![argument isKindOfClass:NSString.class] || [argument length] > 4096) { close(fd); return nil; }
  }
  FILE *input = tmpfile();
  NSData *inputData = [request[@"stdin"] dataUsingEncoding:NSUTF8StringEncoding];
  if (input == NULL || fwrite(inputData.bytes, 1, inputData.length, input) != inputData.length ||
      fflush(input) != 0 || fseek(input, 0, SEEK_SET) != 0 || dup2(fileno(input), STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) {
    if (input != NULL) fclose(input);
    close(fd); return nil;
  }
  fclose(input);
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    for (int attempt = 0; attempt < 150; attempt++) {
      struct pollfd event = { .fd = fd, .events = POLLIN };
      int result = poll(&event, 1, 100);
      if (result > 0 || (result < 0 && errno != EINTR)) _exit(75);
    }
    _exit(76);
  });
  return request;
}
