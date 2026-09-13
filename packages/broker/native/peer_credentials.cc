#include <node_api.h>

#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <map>
#include <net/if.h>
#include <netinet/in.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/stdio.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#ifdef MAC_OPERATOR_NATIVE_FAULT_INJECTION
#include <signal.h>
#endif

namespace {

void ThrowSystemError(napi_env env, const char* message) {
  napi_throw_error(env, nullptr, message);
}

bool ReadString(napi_env env, napi_value value, char* output, size_t capacity) {
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length >= capacity) return false;
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output, capacity, &copied) != napi_ok) return false;
  return copied == length && strlen(output) == length && output[0] == '/';
}

bool ReadComponent(napi_env env, napi_value value, char* output, size_t capacity, const char* required_prefix = nullptr) {
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length >= capacity) return false;
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output, capacity, &copied) != napi_ok ||
      copied != length || strlen(output) != length || strchr(output, '/') != nullptr ||
      strchr(output, '\\') != nullptr) return false;
  if (required_prefix != nullptr && strncmp(output, required_prefix, strlen(required_prefix)) != 0) return false;
  return true;
}

bool ParseUnsigned(const char* value, unsigned long long* output) {
  if (value[0] == '\0') return false;
  char* end = nullptr;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0') return false;
  *output = parsed;
  return true;
}

#ifdef MAC_OPERATOR_NATIVE_FAULT_INJECTION
std::string g_write_fault_point;

void MaybeInjectWriteCrash(const char* point) {
  if (g_write_fault_point == point) {
    kill(getpid(), SIGKILL);
  }
}

napi_value SetWriteFaultPoint(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "setWriteFaultPoint requires one boundary name");
    return nullptr;
  }
  char point[64];
  if (!ReadComponent(env, args[0], point, sizeof(point))) {
    napi_throw_type_error(env, nullptr, "Write fault boundary name is malformed");
    return nullptr;
  }
  g_write_fault_point = point;
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}
#else
void MaybeInjectWriteCrash(const char*) {}
#endif

std::string Sha256Hex(const std::vector<unsigned char>& content) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(content.data(), static_cast<CC_LONG>(content.size()), digest);
  static const char* hex = "0123456789abcdef";
  std::string result;
  result.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (unsigned char byte : digest) {
    result.push_back(hex[(byte >> 4) & 0x0f]);
    result.push_back(hex[byte & 0x0f]);
  }
  return result;
}

std::string HexDigest(const unsigned char* digest, size_t length) {
  static const char* hex = "0123456789abcdef";
  std::string result;
  result.reserve(length * 2);
  for (size_t index = 0; index < length; ++index) {
    result.push_back(hex[(digest[index] >> 4) & 0x0f]);
    result.push_back(hex[digest[index] & 0x0f]);
  }
  return result;
}

bool DescriptorPath(int descriptor, char* output) {
  return fcntl(descriptor, F_GETPATH, output) == 0;
}

bool IsWithinRoot(const char* root, const char* target) {
  size_t root_length = strlen(root);
  if (root_length == 1 && root[0] == '/') return target[0] == '/';
  if (strcmp(root, target) == 0) return true;
  return strncmp(root, target, root_length) == 0 && target[root_length] == '/';
}

void SetString(napi_env env, napi_value object, const char* name, const char* value) {
  napi_value property;
  napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &property);
  napi_set_named_property(env, object, name, property);
}

void SetNumber(napi_env env, napi_value object, const char* name, double value) {
  napi_value property;
  napi_create_double(env, value, &property);
  napi_set_named_property(env, object, name, property);
}

void SetBoolean(napi_env env, napi_value object, const char* name, bool value) {
  napi_value property;
  napi_get_boolean(env, value, &property);
  napi_set_named_property(env, object, name, property);
}

unsigned long long StorageBytes(uint64_t blocks, uint32_t block_size) {
  const __uint128_t bytes = static_cast<__uint128_t>(blocks) * static_cast<__uint128_t>(block_size);
  if (bytes > 100'000'000'000'000ULL) return 100'000'000'000'000ULL;
  return static_cast<unsigned long long>(bytes);
}

struct NetworkInterfaceRecord {
  std::string name;
  bool up;
  std::set<std::string> addresses;
};

std::string SanitizeInterfaceName(const char* value) {
  if (value == nullptr || value[0] == '\0') return "unknown";
  std::string result;
  result.reserve(32);
  for (size_t index = 0; value[index] != '\0' && index < 128; ++index) {
    const unsigned char character = static_cast<unsigned char>(value[index]);
    if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') || character == '.' || character == '_' ||
        character == ':' || character == '@' || character == '/' || character == '+' || character == '-') {
      result.push_back(static_cast<char>(character));
    } else {
      result.push_back('_');
    }
  }
  return result.empty() ? "unknown" : result;
}

bool FormatNetworkAddress(const struct sockaddr* address, std::string* output) {
  if (address == nullptr || output == nullptr) return false;
  char buffer[INET6_ADDRSTRLEN] = {};
  if (address->sa_family == AF_INET && inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(address)->sin_addr,
      buffer, sizeof(buffer)) != nullptr) {
    *output = buffer;
    return true;
  }
  if (address->sa_family == AF_INET6 && inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6*>(address)->sin6_addr,
      buffer, sizeof(buffer)) != nullptr) {
    *output = buffer;
    return true;
  }
  return false;
}

napi_value GetPeerCredentials(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "getPeerCredentials requires one socket descriptor");
    return nullptr;
  }

  int32_t descriptor = -1;
  if (napi_get_value_int32(env, args[0], &descriptor) != napi_ok || descriptor < 0) {
    napi_throw_type_error(env, nullptr, "Socket descriptor must be a non-negative integer");
    return nullptr;
  }

  uid_t user_id = 0;
  gid_t group_id = 0;
  if (getpeereid(descriptor, &user_id, &group_id) != 0) {
    ThrowSystemError(env, "getpeereid failed");
    return nullptr;
  }

  pid_t process_id = 0;
  socklen_t process_id_size = sizeof(process_id);
  if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &process_id, &process_id_size) != 0 ||
      process_id_size != sizeof(process_id)) {
    ThrowSystemError(env, "LOCAL_PEERPID lookup failed");
    return nullptr;
  }

  napi_value result;
  napi_value uid_value;
  napi_value gid_value;
  napi_value pid_value;
  napi_create_object(env, &result);
  napi_create_uint32(env, static_cast<uint32_t>(user_id), &uid_value);
  napi_create_uint32(env, static_cast<uint32_t>(group_id), &gid_value);
  napi_create_int32(env, static_cast<int32_t>(process_id), &pid_value);
  napi_set_named_property(env, result, "uid", uid_value);
  napi_set_named_property(env, result, "gid", gid_value);
  napi_set_named_property(env, result, "pid", pid_value);
  return result;
}

bool ReadDescriptor(napi_env env, napi_value value, int* output) {
  int32_t descriptor = -1;
  if (napi_get_value_int32(env, value, &descriptor) != napi_ok || descriptor < 0) return false;
  *output = descriptor;
  return true;
}

napi_value CreateUnixListener(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2) {
    napi_throw_type_error(env, nullptr, "createUnixListener requires a socket path and backlog");
    return nullptr;
  }

  struct sockaddr_un address{};
  if (!ReadString(env, args[0], address.sun_path, sizeof(address.sun_path))) {
    napi_throw_type_error(env, nullptr, "Unix socket path must be an absolute bounded path");
    return nullptr;
  }
  int32_t backlog = 0;
  if (napi_get_value_int32(env, args[1], &backlog) != napi_ok || backlog < 1 || backlog > 128) {
    napi_throw_type_error(env, nullptr, "Unix socket backlog must be between 1 and 128");
    return nullptr;
  }

  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    ThrowSystemError(env, "Unix socket creation failed");
    return nullptr;
  }
  const auto close_on_error = [descriptor](const char* message) {
    close(descriptor);
    return message;
  };
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket close-on-exec setup failed"));
    return nullptr;
  }
  int no_sigpipe = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket SIGPIPE protection setup failed"));
    return nullptr;
  }
  address.sun_family = AF_UNIX;
  address.sun_len = static_cast<uint8_t>(offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1);
  const socklen_t address_length = static_cast<socklen_t>(address.sun_len);
  if (bind(descriptor, reinterpret_cast<const struct sockaddr*>(&address), address_length) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket bind failed"));
    return nullptr;
  }
  if (chmod(address.sun_path, S_IRUSR | S_IWUSR) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket permission setup failed"));
    return nullptr;
  }
  if (listen(descriptor, backlog) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket listen failed"));
    return nullptr;
  }
  const int flags = fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    ThrowSystemError(env, close_on_error("Unix socket non-blocking setup failed"));
    return nullptr;
  }

  napi_value result;
  napi_create_int32(env, descriptor, &result);
  return result;
}

napi_value AcceptUnixClient(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "acceptUnixClient requires a listener descriptor");
    return nullptr;
  }
  int listener_descriptor = -1;
  if (!ReadDescriptor(env, args[0], &listener_descriptor)) {
    napi_throw_type_error(env, nullptr, "Listener descriptor must be a non-negative integer");
    return nullptr;
  }
  struct sockaddr_un address{};
  socklen_t address_length = sizeof(address);
  const int descriptor = accept(listener_descriptor, reinterpret_cast<struct sockaddr*>(&address), &address_length);
  if (descriptor < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      napi_value null_value;
      napi_get_null(env, &null_value);
      return null_value;
    }
    ThrowSystemError(env, "Unix socket accept failed");
    return nullptr;
  }
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
    close(descriptor);
    ThrowSystemError(env, "Accepted Unix socket close-on-exec setup failed");
    return nullptr;
  }
  int no_sigpipe = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
    close(descriptor);
    ThrowSystemError(env, "Accepted Unix socket SIGPIPE protection setup failed");
    return nullptr;
  }

  uid_t user_id = 0;
  gid_t group_id = 0;
  if (getpeereid(descriptor, &user_id, &group_id) != 0) {
    close(descriptor);
    ThrowSystemError(env, "Accepted Unix socket peer lookup failed");
    return nullptr;
  }
  pid_t process_id = 0;
  socklen_t process_id_size = sizeof(process_id);
  if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &process_id, &process_id_size) != 0 ||
      process_id_size != sizeof(process_id)) {
    close(descriptor);
    ThrowSystemError(env, "Accepted Unix socket peer PID lookup failed");
    return nullptr;
  }

  napi_value result;
  napi_value descriptor_value;
  napi_value uid_value;
  napi_value gid_value;
  napi_value pid_value;
  napi_create_object(env, &result);
  napi_create_int32(env, descriptor, &descriptor_value);
  napi_create_uint32(env, static_cast<uint32_t>(user_id), &uid_value);
  napi_create_uint32(env, static_cast<uint32_t>(group_id), &gid_value);
  napi_create_int32(env, static_cast<int32_t>(process_id), &pid_value);
  napi_set_named_property(env, result, "fd", descriptor_value);
  napi_set_named_property(env, result, "uid", uid_value);
  napi_set_named_property(env, result, "gid", gid_value);
  napi_set_named_property(env, result, "pid", pid_value);
  return result;
}

napi_value CloseUnixDescriptor(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "closeUnixDescriptor requires a descriptor");
    return nullptr;
  }
  int descriptor = -1;
  if (!ReadDescriptor(env, args[0], &descriptor)) {
    napi_throw_type_error(env, nullptr, "Descriptor must be a non-negative integer");
    return nullptr;
  }
  if (close(descriptor) != 0 && errno != EBADF) {
    ThrowSystemError(env, "Unix socket descriptor close failed");
    return nullptr;
  }
  napi_value undefined_value;
  napi_get_undefined(env, &undefined_value);
  return undefined_value;
}

napi_value InspectNetwork(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "inspectNetwork requires includeListeners");
    return nullptr;
  }
  bool include_listeners = false;
  if (napi_get_value_bool(env, args[0], &include_listeners) != napi_ok) {
    napi_throw_type_error(env, nullptr, "includeListeners must be a boolean");
    return nullptr;
  }

  struct ifaddrs* addresses = nullptr;
  if (getifaddrs(&addresses) != 0 || addresses == nullptr) {
    ThrowSystemError(env, "Network interfaces could not be enumerated");
    return nullptr;
  }
  std::map<std::string, NetworkInterfaceRecord> interfaces;
  for (struct ifaddrs* current = addresses; current != nullptr; current = current->ifa_next) {
    const std::string name = SanitizeInterfaceName(current->ifa_name);
    auto found = interfaces.find(name);
    if (found == interfaces.end()) {
      found = interfaces.emplace(name, NetworkInterfaceRecord{name, (current->ifa_flags & IFF_UP) != 0, {}}).first;
    } else if ((current->ifa_flags & IFF_UP) != 0) {
      found->second.up = true;
    }
    std::string formatted;
    if (FormatNetworkAddress(current->ifa_addr, &formatted) && found->second.addresses.size() < 32) {
      found->second.addresses.insert(formatted);
    }
  }
  freeifaddrs(addresses);

  // Listener enumeration uses a private, OS-version-sensitive kernel ABI. Keep this
  // adapter read-only and fail closed until a version-pinned parser is available.
  const bool listener_query_failed = include_listeners;
  const bool listeners_truncated = false;

  napi_value result;
  napi_value interface_array;
  napi_value listener_array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, interfaces.size(), &interface_array);
  size_t interface_index = 0;
  for (const auto& item : interfaces) {
    napi_value value;
    napi_value address_array;
    napi_create_object(env, &value);
    napi_create_array_with_length(env, item.second.addresses.size(), &address_array);
    size_t address_index = 0;
    for (const std::string& address : item.second.addresses) {
      napi_value address_value;
      napi_create_string_utf8(env, address.c_str(), NAPI_AUTO_LENGTH, &address_value);
      napi_set_element(env, address_array, address_index++, address_value);
    }
    SetString(env, value, "name", item.second.name.c_str());
    SetString(env, value, "state", item.second.up ? "up" : "down");
    napi_set_named_property(env, value, "addresses", address_array);
    napi_set_element(env, interface_array, interface_index++, value);
  }
  napi_create_array_with_length(env, 0, &listener_array);
  napi_set_named_property(env, result, "interfaces", interface_array);
  napi_set_named_property(env, result, "listeners", listener_array);
  SetBoolean(env, result, "listenerQueryFailed", listener_query_failed);
  SetBoolean(env, result, "listenersTruncated", listeners_truncated);
  return result;
}

napi_value StatPathWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3) {
    napi_throw_type_error(env, nullptr, "statPathWithinRoot requires root, target, and followSymlink");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  bool follow_symlink = false;
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      napi_get_value_bool(env, args[2], &follow_symlink) != napi_ok) {
    napi_throw_type_error(env, nullptr, "Filesystem paths and followSymlink are malformed");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }

  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  int target_flags = O_RDONLY | O_CLOEXEC;
  if (!follow_symlink) {
    struct stat link_stat;
    if (lstat(requested_target, &link_stat) != 0) {
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem target could not be inspected");
      return nullptr;
    }
    target_flags |= S_ISLNK(link_stat.st_mode) ? O_SYMLINK : O_NOFOLLOW;
  }
  int target_descriptor = open(requested_target, target_flags);
  if (target_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem target could not be opened safely");
    return nullptr;
  }

  struct stat target_stat;
  char resolved_target[PATH_MAX];
  if (fstat(target_descriptor, &target_stat) != 0 || !DescriptorPath(target_descriptor, resolved_target)) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem target identity could not be verified");
    return nullptr;
  }
  if (!IsWithinRoot(resolved_root, resolved_target) || target_stat.st_dev != root_stat.st_dev) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem target escaped the authorized root or volume");
    return nullptr;
  }

  const char* type = "other";
  if (S_ISREG(target_stat.st_mode)) type = "file";
  else if (S_ISDIR(target_stat.st_mode)) type = "directory";
  else if (S_ISLNK(target_stat.st_mode)) type = "symlink";

  char mode[16];
  snprintf(mode, sizeof(mode), "%04o", target_stat.st_mode & 07777);
  char device[32];
  char inode[32];
  snprintf(device, sizeof(device), "%llu", static_cast<unsigned long long>(target_stat.st_dev));
  snprintf(inode, sizeof(inode), "%llu", static_cast<unsigned long long>(target_stat.st_ino));

  napi_value result;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  SetString(env, result, "type", type);
  SetNumber(env, result, "sizeBytes", static_cast<double>(target_stat.st_size));
  SetNumber(env, result, "modifiedAtMs", static_cast<double>(target_stat.st_mtimespec.tv_sec) * 1000.0 +
      static_cast<double>(target_stat.st_mtimespec.tv_nsec) / 1000000.0);
  SetString(env, result, "mode", mode);
  SetBoolean(env, result, "isSymlink", S_ISLNK(target_stat.st_mode));
  SetString(env, result, "device", device);
  SetString(env, result, "inode", inode);

  close(target_descriptor);
  close(root_descriptor);
  return result;
}

napi_value StatStorageVolumeWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "statStorageVolumeWithinRoot requires a root path");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root))) {
    napi_throw_type_error(env, nullptr, "Filesystem root path is malformed");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }

  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem volume identity could not be verified");
    return nullptr;
  }

  const unsigned long long total_bytes = StorageBytes(root_filesystem.f_blocks, root_filesystem.f_bsize);
  const unsigned long long available_bytes = StorageBytes(root_filesystem.f_bavail, root_filesystem.f_bsize);
  const unsigned long long free_bytes = StorageBytes(root_filesystem.f_bfree, root_filesystem.f_bsize);
  const unsigned long long used_bytes = total_bytes >= free_bytes ? total_bytes - free_bytes : 0;

  char id[256];
  snprintf(id, sizeof(id), "dev:%llu:fsid:%d:%d",
      static_cast<unsigned long long>(root_stat.st_dev),
      root_filesystem.f_fsid.val[0], root_filesystem.f_fsid.val[1]);
  const char* filesystem_name = root_filesystem.f_fstypename[0] == '\0' ? "unknown" : root_filesystem.f_fstypename;
  const char* mount_path = root_filesystem.f_mntonname[0] == '\0' ? resolved_root : root_filesystem.f_mntonname;

  napi_value result;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "id", id);
  SetString(env, result, "name", filesystem_name);
  SetString(env, result, "mountPath", mount_path);
  SetNumber(env, result, "totalBytes", static_cast<double>(total_bytes));
  SetNumber(env, result, "availableBytes", static_cast<double>(available_bytes));
  SetNumber(env, result, "usedBytes", static_cast<double>(used_bytes));
  close(root_descriptor);
  return result;
}

struct DirectoryEntryRecord {
  std::string name;
  const char* type;
  off_t size;
  double modified_at_ms;
  bool hidden;
};

napi_value ListDirectoryWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 6;
  napi_value args[6];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 6) {
    napi_throw_type_error(env, nullptr, "listDirectoryWithinRoot requires root, target, includeHidden, cursor, limit, and authorizer");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  bool include_hidden = false;
  int64_t limit = 0;
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      napi_get_value_bool(env, args[2], &include_hidden) != napi_ok ||
      napi_get_value_int64(env, args[4], &limit) != napi_ok || limit < 1 || limit > 500) {
    napi_throw_type_error(env, nullptr, "Filesystem directory-list arguments are malformed");
    return nullptr;
  }
  std::string cursor;
  napi_valuetype cursor_type;
  if (napi_typeof(env, args[3], &cursor_type) != napi_ok) {
    napi_throw_type_error(env, nullptr, "Filesystem directory-list cursor is malformed");
    return nullptr;
  }
  if (cursor_type != napi_undefined && cursor_type != napi_null) {
    size_t cursor_length = 0;
    if (cursor_type != napi_string || napi_get_value_string_utf8(env, args[3], nullptr, 0, &cursor_length) != napi_ok ||
        cursor_length == 0 || cursor_length >= PATH_MAX) {
      napi_throw_type_error(env, nullptr, "Filesystem directory-list cursor is malformed");
      return nullptr;
    }
    cursor.resize(cursor_length, '\0');
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, args[3], cursor.data(), cursor.size() + 1, &copied) != napi_ok || copied != cursor_length) {
      napi_throw_type_error(env, nullptr, "Filesystem directory-list cursor is malformed");
      return nullptr;
    }
  }
  napi_valuetype authorizer_type;
  if (napi_typeof(env, args[5], &authorizer_type) != napi_ok || authorizer_type != napi_function) {
    napi_throw_type_error(env, nullptr, "Filesystem directory-list authorizer must be a function");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }
  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  int target_descriptor = open(requested_target, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (target_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory could not be opened safely");
    return nullptr;
  }
  struct stat target_stat;
  char resolved_target[PATH_MAX];
  if (fstat(target_descriptor, &target_stat) != 0 || !DescriptorPath(target_descriptor, resolved_target) ||
      !S_ISDIR(target_stat.st_mode) || target_stat.st_nlink < 1 ||
      !IsWithinRoot(resolved_root, resolved_target) || target_stat.st_dev != root_stat.st_dev) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory identity is not authorized");
    return nullptr;
  }

  napi_value global;
  napi_value canonical_path;
  napi_value authorization_result;
  napi_get_global(env, &global);
  napi_create_string_utf8(env, resolved_target, NAPI_AUTO_LENGTH, &canonical_path);
  napi_status authorization_status = napi_call_function(
      env, global, args[5], 1, &canonical_path, &authorization_result);
  if (authorization_status != napi_ok) {
    close(target_descriptor);
    close(root_descriptor);
    return nullptr;
  }
  bool target_authorized = false;
  if (napi_get_value_bool(env, authorization_result, &target_authorized) != napi_ok || !target_authorized) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory is denied by policy");
    return nullptr;
  }

  int scan_descriptor = dup(target_descriptor);
  if (scan_descriptor < 0) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory could not be duplicated");
    return nullptr;
  }
  DIR* directory = fdopendir(scan_descriptor);
  if (directory == nullptr) {
    close(scan_descriptor);
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory could not be enumerated");
    return nullptr;
  }

  std::vector<DirectoryEntryRecord> entries;
  entries.reserve(static_cast<size_t>(limit) + 1);
  errno = 0;
  while (struct dirent* entry = readdir(directory)) {
    const char* name = entry->d_name;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
    const bool hidden = name[0] == '.';
    if (hidden && !include_hidden) continue;
    if (cursor.size() > 0 && strcmp(name, cursor.c_str()) <= 0) continue;

    char child_path[PATH_MAX];
    const int written = snprintf(child_path, sizeof(child_path), "%s%s%s", resolved_target,
        (strcmp(resolved_target, "/") == 0 ? "" : "/"), name);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(child_path)) continue;
    napi_value child_value;
    napi_value child_authorized_value;
    napi_create_string_utf8(env, child_path, NAPI_AUTO_LENGTH, &child_value);
    if (napi_call_function(env, global, args[5], 1, &child_value, &child_authorized_value) != napi_ok) {
      closedir(directory);
      close(target_descriptor);
      close(root_descriptor);
      return nullptr;
    }
    bool child_authorized = false;
    if (napi_get_value_bool(env, child_authorized_value, &child_authorized) != napi_ok) {
      closedir(directory);
      close(target_descriptor);
      close(root_descriptor);
      napi_throw_type_error(env, nullptr, "Filesystem directory authorizer returned a malformed result");
      return nullptr;
    }
    if (!child_authorized) continue;

    struct stat entry_stat;
    if (fstatat(target_descriptor, name, &entry_stat, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno == ENOENT) continue;
      closedir(directory);
      close(target_descriptor);
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem directory entry could not be inspected");
      return nullptr;
    }
    if (entry_stat.st_dev != target_stat.st_dev) continue;
    const char* type = "other";
    if (S_ISREG(entry_stat.st_mode)) type = "file";
    else if (S_ISDIR(entry_stat.st_mode)) type = "directory";
    else if (S_ISLNK(entry_stat.st_mode)) type = "symlink";
    entries.push_back({name, type, entry_stat.st_size,
      static_cast<double>(entry_stat.st_mtimespec.tv_sec) * 1000.0 +
        static_cast<double>(entry_stat.st_mtimespec.tv_nsec) / 1000000.0, hidden});
    if (entries.size() > static_cast<size_t>(limit) + 1) {
      std::sort(entries.begin(), entries.end(), [](const DirectoryEntryRecord& left, const DirectoryEntryRecord& right) {
        return left.name < right.name;
      });
      entries.resize(static_cast<size_t>(limit) + 1);
    }
  }
  const int enumeration_error = errno;
  closedir(directory);
  if (enumeration_error != 0) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory enumeration failed");
    return nullptr;
  }
  struct stat readback_stat;
  if (fstat(target_descriptor, &readback_stat) != 0 ||
      readback_stat.st_dev != target_stat.st_dev || readback_stat.st_ino != target_stat.st_ino ||
      readback_stat.st_nlink != target_stat.st_nlink || readback_stat.st_size != target_stat.st_size ||
      readback_stat.st_mtimespec.tv_sec != target_stat.st_mtimespec.tv_sec ||
      readback_stat.st_mtimespec.tv_nsec != target_stat.st_mtimespec.tv_nsec ||
      readback_stat.st_ctimespec.tv_sec != target_stat.st_ctimespec.tv_sec ||
      readback_stat.st_ctimespec.tv_nsec != target_stat.st_ctimespec.tv_nsec) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem directory changed during enumeration");
    return nullptr;
  }
  std::sort(entries.begin(), entries.end(), [](const DirectoryEntryRecord& left, const DirectoryEntryRecord& right) {
    return left.name < right.name;
  });
  const bool has_more = entries.size() > static_cast<size_t>(limit);
  if (entries.size() > static_cast<size_t>(limit)) entries.resize(static_cast<size_t>(limit));

  napi_value result;
  napi_value entry_array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, entries.size(), &entry_array);
  for (size_t index = 0; index < entries.size(); ++index) {
    const DirectoryEntryRecord& entry = entries[index];
    napi_value item;
    napi_create_object(env, &item);
    SetString(env, item, "name", entry.name.c_str());
    SetString(env, item, "type", entry.type);
    SetNumber(env, item, "sizeBytes", static_cast<double>(entry.size));
    SetNumber(env, item, "modifiedAtMs", entry.modified_at_ms);
    SetBoolean(env, item, "hidden", entry.hidden);
    napi_set_element(env, entry_array, index, item);
  }
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  napi_set_named_property(env, result, "entries", entry_array);
  if (has_more && !entries.empty()) SetString(env, result, "nextCursor", entries.back().name.c_str());
  else {
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_set_named_property(env, result, "nextCursor", null_value);
  }
  close(target_descriptor);
  close(root_descriptor);
  return result;
}

napi_value ReadFileWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value args[5];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 5) {
    napi_throw_type_error(env, nullptr, "readFileWithinRoot requires root, target, offset, maxBytes, and authorizer");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  int64_t offset = -1;
  int64_t max_bytes = -1;
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      napi_get_value_int64(env, args[2], &offset) != napi_ok ||
      napi_get_value_int64(env, args[3], &max_bytes) != napi_ok ||
      offset < 0 || offset > 1000000000LL || max_bytes < 0 || max_bytes > 1048576LL) {
    napi_throw_type_error(env, nullptr, "Filesystem read arguments are malformed");
    return nullptr;
  }
  napi_valuetype authorizer_type;
  if (napi_typeof(env, args[4], &authorizer_type) != napi_ok || authorizer_type != napi_function) {
    napi_throw_type_error(env, nullptr, "Filesystem read authorizer must be a function");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }
  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  int target_descriptor = open(requested_target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (target_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file could not be opened safely");
    return nullptr;
  }
  struct stat target_stat;
  char resolved_target[PATH_MAX];
  if (fstat(target_descriptor, &target_stat) != 0 || !DescriptorPath(target_descriptor, resolved_target) ||
      !S_ISREG(target_stat.st_mode) || target_stat.st_nlink != 1 ||
      target_stat.st_size < 0 || target_stat.st_size > 1000000000LL ||
      !IsWithinRoot(resolved_root, resolved_target) || target_stat.st_dev != root_stat.st_dev) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file identity is not authorized");
    return nullptr;
  }

  napi_value global;
  napi_value canonical_path;
  napi_value authorization_result;
  napi_get_global(env, &global);
  napi_create_string_utf8(env, resolved_target, NAPI_AUTO_LENGTH, &canonical_path);
  napi_status authorization_status = napi_call_function(
      env, global, args[4], 1, &canonical_path, &authorization_result);
  if (authorization_status != napi_ok) {
    close(target_descriptor);
    close(root_descriptor);
    return nullptr;
  }

  std::vector<unsigned char> content(static_cast<size_t>(max_bytes));
  ssize_t bytes_read = max_bytes == 0 ? 0 : pread(target_descriptor, content.data(), content.size(), static_cast<off_t>(offset));
  if (bytes_read < 0) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file could not be read");
    return nullptr;
  }
  struct stat readback_stat;
  if (fstat(target_descriptor, &readback_stat) != 0 ||
      readback_stat.st_dev != target_stat.st_dev || readback_stat.st_ino != target_stat.st_ino ||
      readback_stat.st_nlink != 1 || readback_stat.st_size != target_stat.st_size ||
      readback_stat.st_mtimespec.tv_sec != target_stat.st_mtimespec.tv_sec ||
      readback_stat.st_mtimespec.tv_nsec != target_stat.st_mtimespec.tv_nsec ||
      readback_stat.st_ctimespec.tv_sec != target_stat.st_ctimespec.tv_sec ||
      readback_stat.st_ctimespec.tv_nsec != target_stat.st_ctimespec.tv_nsec) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file changed during read");
    return nullptr;
  }

  char device[32];
  char inode[32];
  snprintf(device, sizeof(device), "%llu", static_cast<unsigned long long>(target_stat.st_dev));
  snprintf(inode, sizeof(inode), "%llu", static_cast<unsigned long long>(target_stat.st_ino));
  napi_value result;
  napi_value buffer;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  SetNumber(env, result, "sizeBytes", static_cast<double>(target_stat.st_size));
  SetBoolean(env, result, "truncated", offset + bytes_read < target_stat.st_size);
  SetString(env, result, "device", device);
  SetString(env, result, "inode", inode);
  napi_create_buffer_copy(env, static_cast<size_t>(bytes_read), content.data(), nullptr, &buffer);
  napi_set_named_property(env, result, "content", buffer);

  close(target_descriptor);
  close(root_descriptor);
  return result;
}

napi_value HashFileWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value args[4];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 4) {
    napi_throw_type_error(env, nullptr, "hashFileWithinRoot requires root, target, algorithm, and authorizer");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  char algorithm[16];
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      !ReadComponent(env, args[2], algorithm, sizeof(algorithm)) ||
      (strcmp(algorithm, "sha256") != 0 && strcmp(algorithm, "sha512") != 0)) {
    napi_throw_type_error(env, nullptr, "Filesystem hash arguments are malformed");
    return nullptr;
  }
  napi_valuetype authorizer_type;
  if (napi_typeof(env, args[3], &authorizer_type) != napi_ok || authorizer_type != napi_function) {
    napi_throw_type_error(env, nullptr, "Filesystem hash authorizer must be a function");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }
  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  int target_descriptor = open(requested_target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (target_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file could not be opened safely");
    return nullptr;
  }
  struct stat target_stat;
  char resolved_target[PATH_MAX];
  if (fstat(target_descriptor, &target_stat) != 0 || !DescriptorPath(target_descriptor, resolved_target) ||
      !S_ISREG(target_stat.st_mode) || target_stat.st_nlink != 1 || target_stat.st_size < 0 ||
      target_stat.st_size > 1000000000LL || !IsWithinRoot(resolved_root, resolved_target) ||
      target_stat.st_dev != root_stat.st_dev) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file identity is not authorized");
    return nullptr;
  }

  napi_value global;
  napi_value canonical_path;
  napi_value authorization_result;
  napi_get_global(env, &global);
  napi_create_string_utf8(env, resolved_target, NAPI_AUTO_LENGTH, &canonical_path);
  napi_status authorization_status = napi_call_function(
      env, global, args[3], 1, &canonical_path, &authorization_result);
  if (authorization_status != napi_ok) {
    close(target_descriptor);
    close(root_descriptor);
    return nullptr;
  }

  CC_SHA256_CTX sha256_context;
  CC_SHA512_CTX sha512_context;
  if (strcmp(algorithm, "sha256") == 0) CC_SHA256_Init(&sha256_context);
  else CC_SHA512_Init(&sha512_context);
  std::vector<unsigned char> buffer(1024 * 1024);
  off_t offset = 0;
  while (offset < target_stat.st_size) {
    const size_t remaining = static_cast<size_t>(target_stat.st_size - offset);
    const size_t requested = remaining < buffer.size() ? remaining : buffer.size();
    ssize_t bytes_read = pread(target_descriptor, buffer.data(), requested, offset);
    if (bytes_read < 0 && errno == EINTR) continue;
    if (bytes_read <= 0) {
      close(target_descriptor);
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem file could not be hashed");
      return nullptr;
    }
    if (strcmp(algorithm, "sha256") == 0) {
      CC_SHA256_Update(&sha256_context, buffer.data(), static_cast<CC_LONG>(bytes_read));
    } else {
      CC_SHA512_Update(&sha512_context, buffer.data(), static_cast<CC_LONG>(bytes_read));
    }
    offset += bytes_read;
  }

  struct stat readback_stat;
  if (fstat(target_descriptor, &readback_stat) != 0 ||
      readback_stat.st_dev != target_stat.st_dev || readback_stat.st_ino != target_stat.st_ino ||
      readback_stat.st_nlink != 1 || readback_stat.st_size != target_stat.st_size ||
      readback_stat.st_mtimespec.tv_sec != target_stat.st_mtimespec.tv_sec ||
      readback_stat.st_mtimespec.tv_nsec != target_stat.st_mtimespec.tv_nsec ||
      readback_stat.st_ctimespec.tv_sec != target_stat.st_ctimespec.tv_sec ||
      readback_stat.st_ctimespec.tv_nsec != target_stat.st_ctimespec.tv_nsec) {
    close(target_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem file changed during hash");
    return nullptr;
  }

  unsigned char digest[CC_SHA512_DIGEST_LENGTH];
  size_t digest_length = 0;
  if (strcmp(algorithm, "sha256") == 0) {
    CC_SHA256_Final(digest, &sha256_context);
    digest_length = CC_SHA256_DIGEST_LENGTH;
  } else {
    CC_SHA512_Final(digest, &sha512_context);
    digest_length = CC_SHA512_DIGEST_LENGTH;
  }
  const std::string digest_hex = HexDigest(digest, digest_length);
  char device[32];
  char inode[32];
  snprintf(device, sizeof(device), "%llu", static_cast<unsigned long long>(target_stat.st_dev));
  snprintf(inode, sizeof(inode), "%llu", static_cast<unsigned long long>(target_stat.st_ino));
  napi_value result;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  SetString(env, result, "algorithm", algorithm);
  SetString(env, result, "digest", digest_hex.c_str());
  SetNumber(env, result, "sizeBytes", static_cast<double>(target_stat.st_size));
  SetString(env, result, "device", device);
  SetString(env, result, "inode", inode);
  close(target_descriptor);
  close(root_descriptor);
  return result;
}

napi_value WriteFileAtomicWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 8;
  napi_value args[8];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 8) {
    napi_throw_type_error(env, nullptr, "writeFileAtomicWithinRoot requires root, target, content, createOnly, expectedPresent, expectedDevice, expectedInode, and temporaryName");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  char expected_device[64];
  char expected_inode[64];
  char temporary_name[128];
  bool create_only = false;
  bool expected_present = false;
  bool is_buffer = false;
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      napi_is_buffer(env, args[2], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_value_bool(env, args[3], &create_only) != napi_ok ||
      napi_get_value_bool(env, args[4], &expected_present) != napi_ok ||
      !ReadComponent(env, args[5], expected_device, sizeof(expected_device)) ||
      !ReadComponent(env, args[6], expected_inode, sizeof(expected_inode)) ||
      !ReadComponent(env, args[7], temporary_name, sizeof(temporary_name), ".mac-operator-write-")) {
    napi_throw_type_error(env, nullptr, "Filesystem write arguments are malformed");
    return nullptr;
  }

  void* content_data = nullptr;
  size_t content_length = 0;
  if (napi_get_buffer_info(env, args[2], &content_data, &content_length) != napi_ok || content_length > 1048576) {
    napi_throw_type_error(env, nullptr, "Filesystem write content exceeds the contract limit");
    return nullptr;
  }
  unsigned long long expected_device_number = 0;
  unsigned long long expected_inode_number = 0;
  if (!ParseUnsigned(expected_device, &expected_device_number) || !ParseUnsigned(expected_inode, &expected_inode_number)) {
    napi_throw_type_error(env, nullptr, "Filesystem write identity precondition is malformed");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }
  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  char parent_path[PATH_MAX];
  const char* slash = strrchr(requested_target, '/');
  if (slash == nullptr || slash[1] == '\0') {
    close(root_descriptor);
    napi_throw_type_error(env, nullptr, "Filesystem write target must name a child file");
    return nullptr;
  }
  size_t parent_length = static_cast<size_t>(slash - requested_target);
  if (parent_length == 0) {
    parent_path[0] = '/';
    parent_path[1] = '\0';
  } else if (parent_length >= sizeof(parent_path)) {
    close(root_descriptor);
    napi_throw_type_error(env, nullptr, "Filesystem write parent path is too long");
    return nullptr;
  } else {
    memcpy(parent_path, requested_target, parent_length);
    parent_path[parent_length] = '\0';
  }
  const char* base_name = slash + 1;
  char resolved_parent[PATH_MAX];
  if (realpath(parent_path, resolved_parent) == nullptr ||
      !IsWithinRoot(resolved_root, resolved_parent)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write parent escaped the authorized root");
    return nullptr;
  }
  int parent_descriptor = open(resolved_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write parent could not be opened safely");
    return nullptr;
  }
  struct stat parent_stat;
  char parent_descriptor_path[PATH_MAX];
  if (fstat(parent_descriptor, &parent_stat) != 0 || !DescriptorPath(parent_descriptor, parent_descriptor_path) ||
      !IsWithinRoot(resolved_root, parent_descriptor_path) || parent_stat.st_dev != root_stat.st_dev) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write parent identity is not authorized");
    return nullptr;
  }

  struct stat existing_stat;
  bool existing = false;
  if (fstatat(parent_descriptor, base_name, &existing_stat, AT_SYMLINK_NOFOLLOW) == 0) {
    existing = true;
    if (!S_ISREG(existing_stat.st_mode) || existing_stat.st_nlink != 1 || existing_stat.st_dev != root_stat.st_dev ||
        S_ISLNK(existing_stat.st_mode)) {
      close(parent_descriptor);
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem write target is not an authorized regular file");
      return nullptr;
    }
  } else if (errno != ENOENT) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write target could not be inspected");
    return nullptr;
  }
  if (existing != expected_present || (existing &&
      (static_cast<unsigned long long>(existing_stat.st_dev) != expected_device_number ||
       static_cast<unsigned long long>(existing_stat.st_ino) != expected_inode_number))) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write target identity precondition failed");
    return nullptr;
  }
  if (create_only && existing) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write create-only precondition failed");
    return nullptr;
  }

  int temporary_descriptor = openat(parent_descriptor, temporary_name,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (temporary_descriptor < 0) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write temporary file could not be created");
    return nullptr;
  }
  MaybeInjectWriteCrash("after_temp_create");
  const unsigned char* bytes = static_cast<const unsigned char*>(content_data);
  size_t written = 0;
  while (written < content_length) {
    ssize_t result = write(temporary_descriptor, bytes + written, content_length - written);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) {
      close(temporary_descriptor);
      unlinkat(parent_descriptor, temporary_name, 0);
      close(parent_descriptor);
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem write failed");
      return nullptr;
    }
    written += static_cast<size_t>(result);
  }
  MaybeInjectWriteCrash("after_temp_write");
  if (fsync(temporary_descriptor) != 0) {
    close(temporary_descriptor);
    unlinkat(parent_descriptor, temporary_name, 0);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write could not be durably flushed");
    return nullptr;
  }
  MaybeInjectWriteCrash("after_temp_fsync");
  close(temporary_descriptor);

  int rename_result = create_only
      ? renameatx_np(parent_descriptor, temporary_name, parent_descriptor, base_name, RENAME_EXCL)
      : renameat(parent_descriptor, temporary_name, parent_descriptor, base_name);
  if (rename_result != 0) {
    unlinkat(parent_descriptor, temporary_name, 0);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write could not be atomically committed");
    return nullptr;
  }
  MaybeInjectWriteCrash("after_rename");
  if (fsync(parent_descriptor) != 0) {
    unlinkat(parent_descriptor, temporary_name, 0);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write directory could not be durably flushed");
    return nullptr;
  }
  MaybeInjectWriteCrash("after_directory_fsync");

  int target_descriptor = openat(parent_descriptor, base_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (target_descriptor < 0) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write result could not be reopened");
    return nullptr;
  }
  struct stat target_stat;
  char resolved_target[PATH_MAX];
  if (fstat(target_descriptor, &target_stat) != 0 || !S_ISREG(target_stat.st_mode) || target_stat.st_nlink != 1 ||
      target_stat.st_dev != root_stat.st_dev || target_stat.st_size < 0 || target_stat.st_size > 1048576 ||
      !DescriptorPath(target_descriptor, resolved_target) || !IsWithinRoot(resolved_root, resolved_target) ||
      static_cast<size_t>(target_stat.st_size) != content_length) {
    close(target_descriptor);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write result identity is not authorized");
    return nullptr;
  }
  MaybeInjectWriteCrash("before_readback");

  std::vector<unsigned char> readback(static_cast<size_t>(target_stat.st_size));
  size_t read = 0;
  while (read < readback.size()) {
    ssize_t result = pread(target_descriptor, readback.data() + read, readback.size() - read, static_cast<off_t>(read));
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) {
      close(target_descriptor);
      close(parent_descriptor);
      close(root_descriptor);
      ThrowSystemError(env, "Filesystem write result could not be read back");
      return nullptr;
    }
    read += static_cast<size_t>(result);
  }
  struct stat readback_stat;
  if (fstat(target_descriptor, &readback_stat) != 0 ||
      readback_stat.st_dev != target_stat.st_dev || readback_stat.st_ino != target_stat.st_ino ||
      readback_stat.st_size != target_stat.st_size || readback_stat.st_nlink != 1) {
    close(target_descriptor);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write target changed during readback");
    return nullptr;
  }

  char device[32];
  char inode[32];
  snprintf(device, sizeof(device), "%llu", static_cast<unsigned long long>(target_stat.st_dev));
  snprintf(inode, sizeof(inode), "%llu", static_cast<unsigned long long>(target_stat.st_ino));
  const std::string digest = Sha256Hex(readback);
  napi_value result;
  napi_value readback_buffer;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  SetNumber(env, result, "bytesWritten", static_cast<double>(content_length));
  SetString(env, result, "sha256", digest.c_str());
  SetBoolean(env, result, "created", !existing);
  SetString(env, result, "device", device);
  SetString(env, result, "inode", inode);
  napi_create_buffer_copy(env, readback.size(), readback.data(), nullptr, &readback_buffer);
  napi_set_named_property(env, result, "readback", readback_buffer);

  close(target_descriptor);
  close(parent_descriptor);
  close(root_descriptor);
  return result;
}

napi_value UnlinkFileWithinRoot(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value args[5];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 5) {
    napi_throw_type_error(env, nullptr, "unlinkFileWithinRoot requires root, target, expectedPresent, expectedDevice, and expectedInode");
    return nullptr;
  }

  char configured_root[PATH_MAX];
  char requested_target[PATH_MAX];
  char expected_device[64];
  char expected_inode[64];
  bool expected_present = false;
  if (!ReadString(env, args[0], configured_root, sizeof(configured_root)) ||
      !ReadString(env, args[1], requested_target, sizeof(requested_target)) ||
      napi_get_value_bool(env, args[2], &expected_present) != napi_ok ||
      !ReadComponent(env, args[3], expected_device, sizeof(expected_device)) ||
      !ReadComponent(env, args[4], expected_inode, sizeof(expected_inode))) {
    napi_throw_type_error(env, nullptr, "Filesystem unlink arguments are malformed");
    return nullptr;
  }
  unsigned long long expected_device_number = 0;
  unsigned long long expected_inode_number = 0;
  if (!ParseUnsigned(expected_device, &expected_device_number) || !ParseUnsigned(expected_inode, &expected_inode_number)) {
    napi_throw_type_error(env, nullptr, "Filesystem unlink identity precondition is malformed");
    return nullptr;
  }

  int root_descriptor = open(configured_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    ThrowSystemError(env, "Filesystem root could not be opened safely");
    return nullptr;
  }
  struct stat root_stat;
  struct statfs root_filesystem;
  char resolved_root[PATH_MAX];
  if (fstat(root_descriptor, &root_stat) != 0 || fstatfs(root_descriptor, &root_filesystem) != 0 ||
      (root_filesystem.f_flags & MNT_LOCAL) == 0 || !DescriptorPath(root_descriptor, resolved_root)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem root identity could not be verified");
    return nullptr;
  }

  char parent_path[PATH_MAX];
  const char* slash = strrchr(requested_target, '/');
  if (slash == nullptr || slash[1] == '\0') {
    close(root_descriptor);
    napi_throw_type_error(env, nullptr, "Filesystem unlink target must name a child file");
    return nullptr;
  }
  const size_t parent_length = static_cast<size_t>(slash - requested_target);
  if (parent_length == 0) {
    parent_path[0] = '/';
    parent_path[1] = '\0';
  } else if (parent_length >= sizeof(parent_path)) {
    close(root_descriptor);
    napi_throw_type_error(env, nullptr, "Filesystem unlink parent path is too long");
    return nullptr;
  } else {
    memcpy(parent_path, requested_target, parent_length);
    parent_path[parent_length] = '\0';
  }
  const char* base_name = slash + 1;
  char resolved_parent[PATH_MAX];
  if (realpath(parent_path, resolved_parent) == nullptr || !IsWithinRoot(resolved_root, resolved_parent)) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink parent escaped the authorized root");
    return nullptr;
  }
  int parent_descriptor = open(resolved_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent_descriptor < 0) {
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink parent could not be opened safely");
    return nullptr;
  }
  struct stat parent_stat;
  char parent_descriptor_path[PATH_MAX];
  if (fstat(parent_descriptor, &parent_stat) != 0 || !DescriptorPath(parent_descriptor, parent_descriptor_path) ||
      !IsWithinRoot(resolved_root, parent_descriptor_path) || parent_stat.st_dev != root_stat.st_dev) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink parent identity is not authorized");
    return nullptr;
  }

  struct stat target_stat;
  if (fstatat(parent_descriptor, base_name, &target_stat, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT && !expected_present) {
      char resolved_target[PATH_MAX];
      if (snprintf(resolved_target, sizeof(resolved_target), "%s/%s", resolved_parent, base_name) >= static_cast<int>(sizeof(resolved_target))) {
        close(parent_descriptor);
        close(root_descriptor);
        ThrowSystemError(env, "Filesystem unlink result path is too long");
        return nullptr;
      }
      napi_value result;
      napi_create_object(env, &result);
      SetString(env, result, "rootPath", resolved_root);
      SetString(env, result, "path", resolved_target);
      SetBoolean(env, result, "removed", false);
      SetString(env, result, "device", "0");
      SetString(env, result, "inode", "0");
      close(parent_descriptor);
      close(root_descriptor);
      return result;
    }
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink target could not be inspected");
    return nullptr;
  }
  if (!expected_present || !S_ISREG(target_stat.st_mode) || target_stat.st_nlink != 1 ||
      target_stat.st_dev != root_stat.st_dev || S_ISLNK(target_stat.st_mode) ||
      static_cast<unsigned long long>(target_stat.st_dev) != expected_device_number ||
      static_cast<unsigned long long>(target_stat.st_ino) != expected_inode_number) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink target identity precondition failed");
    return nullptr;
  }

  if (unlinkat(parent_descriptor, base_name, 0) != 0 || fsync(parent_descriptor) != 0) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink could not be durably committed");
    return nullptr;
  }
  struct stat after_stat;
  if (fstatat(parent_descriptor, base_name, &after_stat, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink postcondition failed");
    return nullptr;
  }
  char resolved_target[PATH_MAX];
  if (snprintf(resolved_target, sizeof(resolved_target), "%s/%s", resolved_parent, base_name) >= static_cast<int>(sizeof(resolved_target))) {
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem unlink result path is too long");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  SetString(env, result, "rootPath", resolved_root);
  SetString(env, result, "path", resolved_target);
  SetBoolean(env, result, "removed", true);
  char device[32];
  char inode[32];
  snprintf(device, sizeof(device), "%llu", static_cast<unsigned long long>(target_stat.st_dev));
  snprintf(inode, sizeof(inode), "%llu", static_cast<unsigned long long>(target_stat.st_ino));
  SetString(env, result, "device", device);
  SetString(env, result, "inode", inode);
  close(parent_descriptor);
  close(root_descriptor);
  return result;
}

struct ProcessRecord {
  pid_t pid;
  std::string name;
  std::string executable;
  double cpu_percent;
  uint64_t memory_bytes;
  std::string owner;
};

struct ProcessIdentityRecord {
  pid_t pid;
  pid_t parent_pid;
  uint64_t start_time_micros;
};

bool ReadProcessIdentity(pid_t pid, ProcessIdentityRecord* output) {
  if (pid <= 0 || output == nullptr) return false;
  struct proc_bsdinfo bsd_info{};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != sizeof(bsd_info)) return false;
  constexpr uint64_t MAX_MICROSECONDS = std::numeric_limits<uint64_t>::max();
  if (bsd_info.pbi_start_tvsec > (MAX_MICROSECONDS / 1'000'000ULL) ||
      bsd_info.pbi_start_tvusec > 999'999ULL) return false;
  const uint64_t start_time_micros = bsd_info.pbi_start_tvsec * 1'000'000ULL + bsd_info.pbi_start_tvusec;
  output->pid = pid;
  output->parent_pid = static_cast<pid_t>(bsd_info.pbi_ppid);
  output->start_time_micros = start_time_micros;
  return true;
}

std::string BoundedProcessText(const char* value, size_t capacity) {
  std::string result;
  for (size_t index = 0; index < capacity && value[index] != '\0'; ++index) {
    const unsigned char byte = static_cast<unsigned char>(value[index]);
    if (byte == '\n' || byte == '\r' || byte == '\t' || (byte >= 0x20 && byte != 0x7f)) {
      result.push_back(static_cast<char>(byte));
    } else {
      result.push_back(' ');
    }
  }
  if (result.size() > 4096) result.resize(4096);
  return result.empty() ? "unknown" : result;
}

double ProcessCpuPercent(pid_t pid) {
  uint64_t thread_ids[256] = {};
  const int thread_bytes = proc_pidinfo(pid, PROC_PIDLISTTHREADS, 0, thread_ids, sizeof(thread_ids));
  if (thread_bytes <= 0) return 0.0;
  const size_t thread_count = std::min(static_cast<size_t>(thread_bytes) / sizeof(uint64_t), size_t(256));
  double total = 0.0;
  for (size_t index = 0; index < thread_count; ++index) {
    struct proc_threadinfo thread_info{};
    if (proc_pidinfo(pid, PROC_PIDTHREADINFO, thread_ids[index], &thread_info, sizeof(thread_info)) != sizeof(thread_info)) continue;
    total += std::max(0.0, static_cast<double>(thread_info.pth_cpu_usage) / 10.0);
  }
  return std::min(100.0, total);
}

std::string ProcessState(uint32_t status) {
  switch (status) {
    case SRUN: return "running";
    case SSLEEP: return "sleeping";
    case SSTOP: return "stopped";
    case SZOMB: return "zombie";
    default: return "unknown";
  }
}

napi_value InspectProcess(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "inspectProcess requires pid");
    return nullptr;
  }
  int32_t requested_pid = 0;
  if (napi_get_value_int32(env, args[0], &requested_pid) != napi_ok || requested_pid < 1 || requested_pid > 99'999'999) {
    napi_throw_type_error(env, nullptr, "Process pid must be between 1 and 99999999");
    return nullptr;
  }
  const pid_t pid = static_cast<pid_t>(requested_pid);
  struct proc_bsdinfo bsd_info{};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != sizeof(bsd_info)) {
    ThrowSystemError(env, "Process could not be inspected");
    return nullptr;
  }
  struct proc_taskinfo task_info{};
  const bool task_info_available = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info)) == sizeof(task_info);
  char executable[PROC_PIDPATHINFO_MAXSIZE] = {};
  const bool executable_available = proc_pidpath(pid, executable, sizeof(executable)) > 0;
  std::string name = BoundedProcessText(bsd_info.pbi_name, sizeof(bsd_info.pbi_name));
  if (name == "unknown") name = BoundedProcessText(bsd_info.pbi_comm, sizeof(bsd_info.pbi_comm));
  const std::string executable_text = executable_available ? BoundedProcessText(executable, sizeof(executable)) : "unknown";

  constexpr size_t MAX_CHILDREN = 256;
  std::vector<pid_t> children(MAX_CHILDREN);
  const int child_bytes = proc_listchildpids(pid, children.data(), static_cast<int>(children.size() * sizeof(pid_t)));
  if (child_bytes < 0) {
    children.clear();
  } else {
    const size_t child_count = std::min(static_cast<size_t>(child_bytes) / sizeof(pid_t), children.size());
    children.resize(child_count);
    children.erase(std::remove_if(children.begin(), children.end(), [](pid_t child) { return child <= 0; }), children.end());
    std::sort(children.begin(), children.end());
    children.erase(std::unique(children.begin(), children.end()), children.end());
  }

  char owner[64];
  snprintf(owner, sizeof(owner), "uid:%u", static_cast<unsigned int>(bsd_info.pbi_uid));
  napi_value result;
  napi_value child_array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, children.size(), &child_array);
  for (size_t index = 0; index < children.size(); ++index) {
    napi_value child;
    napi_create_int32(env, static_cast<int32_t>(children[index]), &child);
    napi_set_element(env, child_array, index, child);
  }
  SetNumber(env, result, "pid", static_cast<double>(pid));
  SetString(env, result, "name", name.c_str());
  SetString(env, result, "executable", executable_text.c_str());
  SetString(env, result, "state", ProcessState(bsd_info.pbi_status).c_str());
  SetNumber(env, result, "cpuPercent", task_info_available ? ProcessCpuPercent(pid) : 0.0);
  SetNumber(env, result, "memoryBytes", task_info_available ? static_cast<double>(std::min<uint64_t>(task_info.pti_resident_size, 1'000'000'000'000ULL)) : 0.0);
  if (bsd_info.pbi_ppid > 0) SetNumber(env, result, "parentPid", static_cast<double>(bsd_info.pbi_ppid));
  else {
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_set_named_property(env, result, "parentPid", null_value);
  }
  napi_set_named_property(env, result, "childPids", child_array);
  SetString(env, result, "owner", owner);
  return result;
}

napi_value ListDescendantProcesses(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "listDescendantProcesses requires pid");
    return nullptr;
  }
  int32_t requested_pid = 0;
  if (napi_get_value_int32(env, args[0], &requested_pid) != napi_ok || requested_pid < 1 || requested_pid > 99'999'999) {
    napi_throw_type_error(env, nullptr, "Process pid must be between 1 and 99999999");
    return nullptr;
  }

  const pid_t root_pid = static_cast<pid_t>(requested_pid);
  const int requested_bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
  if (requested_bytes <= 0) {
    ThrowSystemError(env, "Process descendants could not be enumerated");
    return nullptr;
  }
  constexpr size_t MAX_PID_BYTES = 65'536 * sizeof(pid_t);
  const size_t buffer_bytes = std::min(static_cast<size_t>(requested_bytes), MAX_PID_BYTES);
  std::vector<pid_t> pids(buffer_bytes / sizeof(pid_t));
  const int returned_bytes = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(buffer_bytes));
  if (returned_bytes <= 0) {
    ThrowSystemError(env, "Process descendants could not be read");
    return nullptr;
  }
  const size_t pid_count = std::min(static_cast<size_t>(returned_bytes) / sizeof(pid_t), pids.size());
  bool truncated = static_cast<size_t>(requested_bytes) > MAX_PID_BYTES;
  std::vector<ProcessIdentityRecord> identities;
  identities.reserve(pid_count);
  for (size_t index = 0; index < pid_count; ++index) {
    const pid_t pid = pids[index];
    if (pid <= 0) continue;
    ProcessIdentityRecord identity{};
    if (ReadProcessIdentity(pid, &identity)) identities.push_back(identity);
  }

  std::set<pid_t> known;
  known.insert(root_pid);
  std::vector<pid_t> queue{root_pid};
  std::vector<ProcessIdentityRecord> descendants;
  for (size_t queue_index = 0; queue_index < queue.size(); ++queue_index) {
    const pid_t parent_pid = queue[queue_index];
    for (const ProcessIdentityRecord& identity : identities) {
      if (identity.parent_pid != parent_pid || known.find(identity.pid) != known.end()) continue;
      if (descendants.size() >= 256) {
        truncated = true;
        break;
      }
      known.insert(identity.pid);
      descendants.push_back(identity);
      queue.push_back(identity.pid);
    }
    if (truncated && descendants.size() >= 256) break;
  }

  napi_value result;
  napi_value process_array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, descendants.size(), &process_array);
  for (size_t index = 0; index < descendants.size(); ++index) {
    const ProcessIdentityRecord& identity = descendants[index];
    napi_value item;
    napi_create_object(env, &item);
    SetNumber(env, item, "pid", static_cast<double>(identity.pid));
    SetNumber(env, item, "parentPid", static_cast<double>(identity.parent_pid));
    SetNumber(env, item, "startTimeMicros", static_cast<double>(identity.start_time_micros));
    napi_set_element(env, process_array, index, item);
  }
  napi_set_named_property(env, result, "processes", process_array);
  SetBoolean(env, result, "truncated", truncated);
  return result;
}

napi_value IsProcessIdentityAlive(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2) {
    napi_throw_type_error(env, nullptr, "isProcessIdentityAlive requires pid and start time");
    return nullptr;
  }
  int32_t requested_pid = 0;
  double requested_start_time = 0;
  if (napi_get_value_int32(env, args[0], &requested_pid) != napi_ok || requested_pid < 1 || requested_pid > 99'999'999 ||
      napi_get_value_double(env, args[1], &requested_start_time) != napi_ok || requested_start_time < 0 ||
      requested_start_time > 9'007'199'254'740'991.0) {
    napi_throw_type_error(env, nullptr, "Process identity is malformed");
    return nullptr;
  }
  ProcessIdentityRecord identity{};
  const bool alive = ReadProcessIdentity(static_cast<pid_t>(requested_pid), &identity) &&
    static_cast<double>(identity.start_time_micros) == requested_start_time;
  napi_value result;
  napi_get_boolean(env, alive, &result);
  return result;
}

napi_value ListProcesses(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2) {
    napi_throw_type_error(env, nullptr, "listProcesses requires limit and sort");
    return nullptr;
  }
  int32_t limit = 0;
  if (napi_get_value_int32(env, args[0], &limit) != napi_ok || limit < 1 || limit > 500) {
    napi_throw_type_error(env, nullptr, "Process limit must be between 1 and 500");
    return nullptr;
  }
  size_t sort_length = 0;
  if (napi_get_value_string_utf8(env, args[1], nullptr, 0, &sort_length) != napi_ok || sort_length == 0 || sort_length > 16) {
    napi_throw_type_error(env, nullptr, "Process sort is malformed");
    return nullptr;
  }
  std::string sort(sort_length, '\0');
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, args[1], sort.data(), sort.size() + 1, &copied) != napi_ok || copied != sort_length ||
      (sort != "cpu" && sort != "memory" && sort != "pid" && sort != "name")) {
    napi_throw_type_error(env, nullptr, "Process sort is unsupported");
    return nullptr;
  }

  const int requested_bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
  if (requested_bytes <= 0) {
    ThrowSystemError(env, "Process inventory could not be enumerated");
    return nullptr;
  }
  constexpr size_t MAX_PID_BYTES = 65'536 * sizeof(pid_t);
  const size_t buffer_bytes = std::min(static_cast<size_t>(requested_bytes), MAX_PID_BYTES);
  std::vector<pid_t> pids(buffer_bytes / sizeof(pid_t));
  const int returned_bytes = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(buffer_bytes));
  if (returned_bytes <= 0) {
    ThrowSystemError(env, "Process inventory could not be read");
    return nullptr;
  }
  const size_t pid_count = std::min(static_cast<size_t>(returned_bytes) / sizeof(pid_t), pids.size());
  const bool inventory_truncated = static_cast<size_t>(requested_bytes) > MAX_PID_BYTES;
  std::vector<ProcessRecord> records;
  records.reserve(std::min(pid_count, static_cast<size_t>(limit)));
  std::set<pid_t> seen;
  for (size_t index = 0; index < pid_count; ++index) {
    const pid_t pid = pids[index];
    if (pid <= 0 || !seen.insert(pid).second) continue;
    struct proc_bsdinfo bsd_info{};
    struct proc_taskinfo task_info{};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != sizeof(bsd_info) ||
        proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info)) != sizeof(task_info)) continue;
    char executable[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_pidpath(pid, executable, sizeof(executable)) <= 0) continue;
    std::string executable_text = BoundedProcessText(executable, sizeof(executable));
    std::string name = BoundedProcessText(bsd_info.pbi_name, sizeof(bsd_info.pbi_name));
    if (name == "unknown") name = BoundedProcessText(bsd_info.pbi_comm, sizeof(bsd_info.pbi_comm));
    char owner[64];
    snprintf(owner, sizeof(owner), "uid:%u", static_cast<unsigned int>(bsd_info.pbi_uid));
    records.push_back({pid, name, executable_text, ProcessCpuPercent(pid),
      std::min<uint64_t>(task_info.pti_resident_size, 1'000'000'000'000ULL), owner});
  }
  std::sort(records.begin(), records.end(), [&sort](const ProcessRecord& left, const ProcessRecord& right) {
    if (sort == "cpu" && left.cpu_percent != right.cpu_percent) return left.cpu_percent > right.cpu_percent;
    if (sort == "memory" && left.memory_bytes != right.memory_bytes) return left.memory_bytes > right.memory_bytes;
    if (sort == "name" && left.name != right.name) return left.name < right.name;
    return left.pid < right.pid;
  });
  const bool truncated = inventory_truncated || records.size() > static_cast<size_t>(limit);
  if (records.size() > static_cast<size_t>(limit)) records.resize(static_cast<size_t>(limit));

  napi_value result;
  napi_value process_array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, records.size(), &process_array);
  for (size_t index = 0; index < records.size(); ++index) {
    const ProcessRecord& process = records[index];
    napi_value item;
    napi_create_object(env, &item);
    SetNumber(env, item, "pid", static_cast<double>(process.pid));
    SetString(env, item, "name", process.name.c_str());
    SetString(env, item, "executable", process.executable.c_str());
    SetNumber(env, item, "cpuPercent", process.cpu_percent);
    SetNumber(env, item, "memoryBytes", static_cast<double>(process.memory_bytes));
    SetString(env, item, "owner", process.owner.c_str());
    napi_set_element(env, process_array, index, item);
  }
  napi_set_named_property(env, result, "processes", process_array);
  SetBoolean(env, result, "truncated", truncated);
  return result;
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value function;
  napi_create_function(env, "getPeerCredentials", NAPI_AUTO_LENGTH, GetPeerCredentials, nullptr, &function);
  napi_set_named_property(env, exports, "getPeerCredentials", function);
  napi_create_function(env, "createUnixListener", NAPI_AUTO_LENGTH, CreateUnixListener, nullptr, &function);
  napi_set_named_property(env, exports, "createUnixListener", function);
  napi_create_function(env, "acceptUnixClient", NAPI_AUTO_LENGTH, AcceptUnixClient, nullptr, &function);
  napi_set_named_property(env, exports, "acceptUnixClient", function);
  napi_create_function(env, "closeUnixDescriptor", NAPI_AUTO_LENGTH, CloseUnixDescriptor, nullptr, &function);
  napi_set_named_property(env, exports, "closeUnixDescriptor", function);
  napi_create_function(env, "inspectNetwork", NAPI_AUTO_LENGTH, InspectNetwork, nullptr, &function);
  napi_set_named_property(env, exports, "inspectNetwork", function);
  napi_create_function(env, "statPathWithinRoot", NAPI_AUTO_LENGTH, StatPathWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "statPathWithinRoot", function);
  napi_create_function(env, "statStorageVolumeWithinRoot", NAPI_AUTO_LENGTH, StatStorageVolumeWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "statStorageVolumeWithinRoot", function);
  napi_create_function(env, "listDirectoryWithinRoot", NAPI_AUTO_LENGTH, ListDirectoryWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "listDirectoryWithinRoot", function);
  napi_create_function(env, "readFileWithinRoot", NAPI_AUTO_LENGTH, ReadFileWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "readFileWithinRoot", function);
  napi_create_function(env, "hashFileWithinRoot", NAPI_AUTO_LENGTH, HashFileWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "hashFileWithinRoot", function);
  napi_create_function(env, "writeFileAtomicWithinRoot", NAPI_AUTO_LENGTH, WriteFileAtomicWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "writeFileAtomicWithinRoot", function);
#ifdef MAC_OPERATOR_NATIVE_FAULT_INJECTION
  napi_create_function(env, "setWriteFaultPoint", NAPI_AUTO_LENGTH, SetWriteFaultPoint, nullptr, &function);
  napi_set_named_property(env, exports, "setWriteFaultPoint", function);
#endif
  napi_create_function(env, "unlinkFileWithinRoot", NAPI_AUTO_LENGTH, UnlinkFileWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "unlinkFileWithinRoot", function);
  napi_create_function(env, "listProcesses", NAPI_AUTO_LENGTH, ListProcesses, nullptr, &function);
  napi_set_named_property(env, exports, "listProcesses", function);
  napi_create_function(env, "inspectProcess", NAPI_AUTO_LENGTH, InspectProcess, nullptr, &function);
  napi_set_named_property(env, exports, "inspectProcess", function);
  napi_create_function(env, "listDescendantProcesses", NAPI_AUTO_LENGTH, ListDescendantProcesses, nullptr, &function);
  napi_set_named_property(env, exports, "listDescendantProcesses", function);
  napi_create_function(env, "isProcessIdentityAlive", NAPI_AUTO_LENGTH, IsProcessIdentityAlive, nullptr, &function);
  napi_set_named_property(env, exports, "isProcessIdentityAlive", function);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
