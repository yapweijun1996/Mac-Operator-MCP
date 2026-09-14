#include <node_api.h>

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#include <CommonCrypto/CommonDigest.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint64_t kMaxImageBytes = 512ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr size_t kDigestChunkBytes = 1024 * 1024;

void ThrowError(napi_env env, const char* message) {
  napi_throw_error(env, nullptr, message);
}

bool ReadString(napi_env env, napi_value value, char* output, size_t capacity) {
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length >= capacity) return false;
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output, capacity, &copied) != napi_ok ||
      copied != length || strlen(output) != length) return false;
  return true;
}

bool IsSha256(const char* value) {
  if (strlen(value) != CC_SHA256_DIGEST_LENGTH * 2) return false;
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH * 2; ++index) {
    const char character = value[index];
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) return false;
  }
  return true;
}

bool IsUnsignedDecimal(const char* value) {
  if (value[0] == '\0') return false;
  for (const char* cursor = value; *cursor != '\0'; ++cursor) {
    if (*cursor < '0' || *cursor > '9') return false;
  }
  return true;
}

bool SameIdentity(const struct stat& left, const struct stat& right) {
  return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
      left.st_size == right.st_size && left.st_mode == right.st_mode &&
      left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
      left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
      left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
      left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
}

std::string Sha256Hex(const unsigned char* digest) {
  static const char* hex = "0123456789abcdef";
  std::string output;
  output.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
    output.push_back(hex[(digest[index] >> 4) & 0x0f]);
    output.push_back(hex[digest[index] & 0x0f]);
  }
  return output;
}

bool HashDescriptor(int descriptor, off_t size, std::string* digest) {
  if (descriptor < 0 || size < 1 || static_cast<uint64_t>(size) > kMaxImageBytes) return false;
  CC_SHA256_CTX context;
  if (CC_SHA256_Init(&context) != 1) return false;
  std::vector<unsigned char> buffer(kDigestChunkBytes);
  off_t offset = 0;
  while (offset < size) {
    const size_t wanted = static_cast<size_t>(std::min<off_t>(
        static_cast<off_t>(buffer.size()), size - offset));
    ssize_t received;
    do {
      received = pread(descriptor, buffer.data(), wanted, offset);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(wanted)) return false;
    if (CC_SHA256_Update(&context, buffer.data(), static_cast<CC_LONG>(received)) != 1) return false;
    offset += received;
  }
  unsigned char output[CC_SHA256_DIGEST_LENGTH];
  if (CC_SHA256_Final(output, &context) != 1) return false;
  *digest = Sha256Hex(output);
  return true;
}

void SetBoolean(napi_env env, napi_value object, const char* name, bool value) {
  napi_value property;
  napi_get_boolean(env, value, &property);
  napi_set_named_property(env, object, name, property);
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

napi_value InspectGuestConfiguration(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value args[4];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 4) {
    napi_throw_type_error(env, nullptr,
        "inspectGuestConfiguration requires path, device, inode, and sha256");
    return nullptr;
  }

  char requested_path[PATH_MAX];
  char expected_device[64];
  char expected_inode[64];
  char expected_digest[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  if (!ReadString(env, args[0], requested_path, sizeof(requested_path)) ||
      !ReadString(env, args[1], expected_device, sizeof(expected_device)) ||
      !ReadString(env, args[2], expected_inode, sizeof(expected_inode)) ||
      !ReadString(env, args[3], expected_digest, sizeof(expected_digest)) ||
      requested_path[0] != '/' || !IsUnsignedDecimal(expected_device) ||
      !IsUnsignedDecimal(expected_inode) || !IsSha256(expected_digest)) {
    napi_throw_type_error(env, nullptr, "Guest image identity arguments are malformed");
    return nullptr;
  }

  struct stat requested_stat{};
  if (lstat(requested_path, &requested_stat) != 0 || S_ISLNK(requested_stat.st_mode)) {
    ThrowError(env, "Guest image must be an owner-only regular file, not a symlink");
    return nullptr;
  }
  char canonical_path[PATH_MAX];
  if (realpath(requested_path, canonical_path) == nullptr ||
      strcmp(requested_path, canonical_path) != 0) {
    ThrowError(env, "Guest image path is not canonical");
    return nullptr;
  }
  struct stat path_stat{};
  const uid_t current_uid = getuid();
  if (lstat(canonical_path, &path_stat) != 0 || !S_ISREG(path_stat.st_mode) ||
      path_stat.st_uid != current_uid || (path_stat.st_mode & 0077) != 0 ||
      path_stat.st_size < 1 || static_cast<uint64_t>(path_stat.st_size) > kMaxImageBytes ||
      std::to_string(static_cast<unsigned long long>(path_stat.st_dev)) != expected_device ||
      std::to_string(static_cast<unsigned long long>(path_stat.st_ino)) != expected_inode) {
    ThrowError(env, "Guest image identity or protection precondition failed");
    return nullptr;
  }

  const int descriptor = open(canonical_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) {
    ThrowError(env, "Guest image could not be opened safely");
    return nullptr;
  }
  struct stat opened_stat{};
  std::string digest;
  const bool opened = fstat(descriptor, &opened_stat) == 0 &&
      SameIdentity(opened_stat, path_stat) &&
      HashDescriptor(descriptor, opened_stat.st_size, &digest);
  struct stat readback_stat{};
  const bool stable = opened && fstat(descriptor, &readback_stat) == 0 &&
      SameIdentity(readback_stat, path_stat) && digest == expected_digest;
  close(descriptor);
  if (!stable) {
    ThrowError(env, "Guest image digest or identity changed during preflight");
    return nullptr;
  }

  @autoreleasepool {
    NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:canonical_path]];
    NSError* attachment_error = nil;
    VZDiskImageStorageDeviceAttachment* attachment =
        [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:url readOnly:YES error:&attachment_error];
    if (attachment == nil) {
      ThrowError(env, "Guest image is not an accepted raw disk image");
      return nullptr;
    }

    VZVirtualMachineConfiguration* configuration =
        [[VZVirtualMachineConfiguration alloc] init];
    configuration.platform = [[VZGenericPlatformConfiguration alloc] init];
    configuration.bootLoader = [[VZEFIBootLoader alloc] init];
    configuration.CPUCount = VZVirtualMachineConfiguration.minimumAllowedCPUCount;
    configuration.memorySize = VZVirtualMachineConfiguration.minimumAllowedMemorySize;
    configuration.storageDevices = @[
      [[VZVirtioBlockDeviceConfiguration alloc] initWithAttachment:attachment]
    ];
    configuration.networkDevices = @[];
    configuration.directorySharingDevices = @[];
    configuration.serialPorts = @[];
    configuration.socketDevices = @[];

    NSError* validation_error = nil;
    const BOOL configuration_valid = [configuration validateWithError:&validation_error];
    napi_value result;
    napi_create_object(env, &result);
    SetString(env, result, "path", canonical_path);
    SetString(env, result, "device", expected_device);
    SetString(env, result, "inode", expected_inode);
    SetString(env, result, "sha256", digest.c_str());
    SetNumber(env, result, "sizeBytes", static_cast<double>(path_stat.st_size));
    SetBoolean(env, result, "readOnlyAttachment", attachment.readOnly);
    SetBoolean(env, result, "configurationValid", configuration_valid);
    SetBoolean(env, result, "vmBootAttempted", false);
    SetBoolean(env, result, "hostNetworkAttached", configuration.networkDevices.count > 0);
    SetBoolean(env, result, "hostDirectorySharingAttached", configuration.directorySharingDevices.count > 0);
    return result;
  }
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value version;
  napi_create_uint32(env, NAPI_VERSION, &version);
  napi_set_named_property(env, exports, "nativeNapiVersion", version);
  napi_value function;
  napi_create_function(env, "inspectGuestConfiguration", NAPI_AUTO_LENGTH,
      InspectGuestConfiguration, nullptr, &function);
  napi_set_named_property(env, exports, "inspectGuestConfiguration", function);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
