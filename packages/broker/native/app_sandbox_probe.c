#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

static void print_operation(const char* operation, const char* path, int allowed, int error_number) {
  printf("{\"operation\":\"%s\",\"path\":\"%s\",\"allowed\":%s,\"errno\":%d}\n",
         operation, path, allowed ? "true" : "false", error_number);
}

static int probe_read(const char* path) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    print_operation("read", path, 0, errno);
    return 0;
  }
  char buffer[1];
  const ssize_t result = read(fd, buffer, sizeof(buffer));
  const int error_number = result < 0 ? errno : 0;
  close(fd);
  print_operation("read", path, result >= 0, error_number);
  return result >= 0;
}

static int probe_write(const char* path) {
  const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    print_operation("write", path, 0, errno);
    return 0;
  }
  const char marker[] = "mac-operator-app-sandbox-probe\n";
  const ssize_t result = write(fd, marker, sizeof(marker) - 1);
  const int error_number = result < 0 ? errno : 0;
  close(fd);
  print_operation("write", path, result == (ssize_t)(sizeof(marker) - 1), error_number);
  return result == (ssize_t)(sizeof(marker) - 1);
}

static int probe_child_write(const char* path) {
  pid_t child = 0;
  char* const arguments[] = {"/usr/bin/touch", (char*)path, NULL};
  const int spawn_result = posix_spawn(&child, "/usr/bin/touch", NULL, NULL, arguments, environ);
  if (spawn_result != 0) {
    print_operation("child-write", path, 0, spawn_result);
    return 0;
  }
  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    print_operation("child-write", path, 0, errno);
    return 0;
  }
  const int allowed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  print_operation("child-write", path, allowed, allowed ? 0 : (WIFEXITED(status) ? WEXITSTATUS(status) : 128));
  return allowed;
}

static int probe_network_connect(const char* host, int port) {
  int descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (descriptor < 0) {
    print_operation("network-connect", host, 0, errno);
    return 0;
  }
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons((uint16_t)port);
  const int parsed = inet_pton(AF_INET, host, &address.sin_addr);
  int error_number = 0;
  int allowed = 0;
  if (parsed == 1) {
    allowed = connect(descriptor, (const struct sockaddr*)&address, sizeof(address)) == 0;
    if (!allowed) error_number = errno;
  } else {
    error_number = parsed == 0 ? EINVAL : errno;
  }
  close(descriptor);
  print_operation("network-connect", host, allowed, error_number);
  return allowed;
}

static int probe_persistence_write(const char* path) {
  const int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    print_operation("persistence-write", path, 0, errno);
    return 0;
  }
  const char marker[] = "<?xml version=\"1.0\"?><plist/>\n";
  const ssize_t result = write(descriptor, marker, sizeof(marker) - 1);
  const int error_number = result < 0 ? errno : 0;
  close(descriptor);
  print_operation("persistence-write", path, result == (ssize_t)(sizeof(marker) - 1), error_number);
  return result == (ssize_t)(sizeof(marker) - 1);
}

static int probe_credential_zone(const char* path) {
  const int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (descriptor < 0) {
    print_operation("credential-zone-open", path, 0, errno);
    return 0;
  }
  close(descriptor);
  print_operation("credential-zone-open", path, 1, 0);
  return 1;
}

int main(int argc, char** argv) {
  if (argc != 15 || strcmp(argv[1], "--read") != 0 || strcmp(argv[3], "--write") != 0 ||
      strcmp(argv[5], "--child-write") != 0 || strcmp(argv[7], "--connect-host") != 0 ||
      strcmp(argv[9], "--connect-port") != 0 || strcmp(argv[11], "--persistence") != 0 ||
      strcmp(argv[13], "--credential-zone") != 0) {
    fprintf(stderr, "usage: app_sandbox_probe --read PATH --write PATH --child-write PATH --connect-host HOST --connect-port PORT --persistence PATH --credential-zone PATH\n");
    return 64;
  }
  const int read_allowed = probe_read(argv[2]);
  const int write_allowed = probe_write(argv[4]);
  const int child_write_allowed = probe_child_write(argv[6]);
  const int port = (int)strtol(argv[10], NULL, 10);
  const int network_allowed = port > 0 && port <= 65535 ? probe_network_connect(argv[8], port) : 0;
  const int persistence_allowed = probe_persistence_write(argv[12]);
  const int credential_zone_allowed = probe_credential_zone(argv[14]);
  return !read_allowed && write_allowed && !child_write_allowed && !network_allowed &&
      !persistence_allowed && !credential_zone_allowed ? 0 : 1;
}
