#include <node_api.h>

#include <CommonCrypto/CommonDigest.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/stdio.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

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
  if (fsync(temporary_descriptor) != 0) {
    close(temporary_descriptor);
    unlinkat(parent_descriptor, temporary_name, 0);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write could not be durably flushed");
    return nullptr;
  }
  close(temporary_descriptor);

  int rename_result = create_only
      ? renameatx_np(parent_descriptor, temporary_name, parent_descriptor, base_name, RENAME_EXCL)
      : renameat(parent_descriptor, temporary_name, parent_descriptor, base_name);
  if (rename_result != 0 || fsync(parent_descriptor) != 0) {
    unlinkat(parent_descriptor, temporary_name, 0);
    close(parent_descriptor);
    close(root_descriptor);
    ThrowSystemError(env, "Filesystem write could not be atomically committed");
    return nullptr;
  }

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

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value function;
  napi_create_function(env, "getPeerCredentials", NAPI_AUTO_LENGTH, GetPeerCredentials, nullptr, &function);
  napi_set_named_property(env, exports, "getPeerCredentials", function);
  napi_create_function(env, "statPathWithinRoot", NAPI_AUTO_LENGTH, StatPathWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "statPathWithinRoot", function);
  napi_create_function(env, "readFileWithinRoot", NAPI_AUTO_LENGTH, ReadFileWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "readFileWithinRoot", function);
  napi_create_function(env, "hashFileWithinRoot", NAPI_AUTO_LENGTH, HashFileWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "hashFileWithinRoot", function);
  napi_create_function(env, "writeFileAtomicWithinRoot", NAPI_AUTO_LENGTH, WriteFileAtomicWithinRoot, nullptr, &function);
  napi_set_named_property(env, exports, "writeFileAtomicWithinRoot", function);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
