#include <node_api.h>

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

@interface MOPVirtualizationGuestHandle : NSObject {
@public
  uint64_t magic;
}
@property(nonatomic, strong) VZVirtualMachine* machine;
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, copy) NSString* imagePath;
@property(nonatomic, copy) NSString* imageSha256;
@property(nonatomic, copy) NSString* runtimeVersion;
@property(nonatomic, copy) NSString* bootId;
@property(nonatomic, assign) BOOL closed;
@end

@implementation MOPVirtualizationGuestHandle
@end

namespace {

constexpr uint64_t kMaxImageBytes = 512ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr size_t kDigestChunkBytes = 1024 * 1024;
constexpr uint64_t kHandleMagic = 0x4d4f50565a4c4946ULL;
constexpr uint64_t kNativeOperationTimeoutNs = 15ULL * 60ULL * 1000000000ULL;

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

bool IsRuntimeVersion(const char* value) {
  const size_t length = strlen(value);
  if (length == 0 || length > 128) return false;
  for (size_t index = 0; index < length; ++index) {
    const char character = value[index];
    if (!((character >= 'a' && character <= 'z') ||
          (character >= 'A' && character <= 'Z') ||
          (character >= '0' && character <= '9') ||
          character == '.' || character == ':' || character == '_' ||
          character == '+' || character == '-' || character == '/')) return false;
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

bool ValidateImage(const char* requested_path, const char* expected_device,
                   const char* expected_inode, const char* expected_digest,
                   std::string* canonical_path) {
  if (requested_path[0] != '/' || !IsUnsignedDecimal(expected_device) ||
      !IsUnsignedDecimal(expected_inode) || !IsSha256(expected_digest)) return false;
  struct stat requested_stat{};
  if (lstat(requested_path, &requested_stat) != 0 || S_ISLNK(requested_stat.st_mode)) return false;
  char resolved_path[PATH_MAX];
  if (realpath(requested_path, resolved_path) == nullptr ||
      strcmp(requested_path, resolved_path) != 0) return false;
  struct stat path_stat{};
  const uid_t current_uid = getuid();
  if (lstat(resolved_path, &path_stat) != 0 || !S_ISREG(path_stat.st_mode) ||
      path_stat.st_uid != current_uid || (path_stat.st_mode & 0077) != 0 ||
      path_stat.st_size < 1 || static_cast<uint64_t>(path_stat.st_size) > kMaxImageBytes ||
      std::to_string(static_cast<unsigned long long>(path_stat.st_dev)) != expected_device ||
      std::to_string(static_cast<unsigned long long>(path_stat.st_ino)) != expected_inode) return false;

  const int descriptor = open(resolved_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) return false;
  struct stat opened_stat{};
  std::string digest;
  const bool opened = fstat(descriptor, &opened_stat) == 0 &&
      SameIdentity(opened_stat, path_stat) && HashDescriptor(descriptor, opened_stat.st_size, &digest);
  struct stat readback_stat{};
  const bool stable = opened && fstat(descriptor, &readback_stat) == 0 &&
      SameIdentity(readback_stat, path_stat) && digest == expected_digest;
  close(descriptor);
  if (!stable) return false;
  *canonical_path = resolved_path;
  return true;
}

MOPVirtualizationGuestHandle* ReadHandle(napi_env env, napi_value value) {
  void* data = nullptr;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == nullptr) {
    napi_throw_type_error(env, nullptr, "Virtualization guest VM handle is invalid");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = (__bridge MOPVirtualizationGuestHandle*)data;
  if (handle->magic != kHandleMagic) {
    napi_throw_type_error(env, nullptr, "Virtualization guest VM handle is invalid");
    return nullptr;
  }
  return handle;
}

void FinalizeHandle(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  if (data != nullptr) {
    MOPVirtualizationGuestHandle* handle = (__bridge_transfer MOPVirtualizationGuestHandle*)data;
    handle->magic = 0;
    handle.machine = nil;
    handle.queue = nil;
  }
}

void SetString(napi_env env, napi_value object, const char* name, const char* value) {
  napi_value property;
  napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &property);
  napi_set_named_property(env, object, name, property);
}

void SetNull(napi_env env, napi_value object, const char* name) {
  napi_value property;
  napi_get_null(env, &property);
  napi_set_named_property(env, object, name, property);
}

void SetGuestIdentity(napi_env env, napi_value object, MOPVirtualizationGuestHandle* handle) {
  napi_value identity;
  napi_create_object(env, &identity);
  const char* image_sha256 = [handle.imageSha256 UTF8String];
  const char* runtime_version = [handle.runtimeVersion UTF8String];
  SetString(env, identity, "imageSha256", image_sha256 == nullptr ? "" : image_sha256);
  SetString(env, identity, "runtimeVersion", runtime_version == nullptr ? "" : runtime_version);
  napi_set_named_property(env, object, "guestIdentity", identity);
}

NSString* NewBootId() {
  uint8_t bytes[16];
  arc4random_buf(bytes, sizeof(bytes));
  static const char* hex = "0123456789abcdef";
  char output[5 + sizeof(bytes) * 2 + 1];
  memcpy(output, "vz-", 3);
  for (size_t index = 0; index < sizeof(bytes); ++index) {
    output[3 + index * 2] = hex[(bytes[index] >> 4) & 0x0f];
    output[4 + index * 2] = hex[bytes[index] & 0x0f];
  }
  output[3 + sizeof(bytes) * 2] = '\0';
  return [NSString stringWithUTF8String:output];
}

const char* StateName(VZVirtualMachineState state) {
  switch (state) {
    case VZVirtualMachineStateRunning: return "running";
    case VZVirtualMachineStateStopped: return "stopped";
    default: return "unknown";
  }
}

struct WaitState {
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  std::mutex mutex;
  bool completed = false;
  std::string error;
  std::string state;
  std::string boot_id;
};

struct AsyncOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  void* retained_handle = nullptr;
  MOPVirtualizationGuestHandle* handle = nullptr;
  bool start = false;
  std::string expected_boot_id;
  std::string boot_id;
  std::string error;
  bool timed_out = false;
};

struct AsyncStatusOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  void* retained_handle = nullptr;
  MOPVirtualizationGuestHandle* handle = nullptr;
  std::string state;
  std::string boot_id;
  std::string error;
  bool timed_out = false;
};

void RecordCompletion(const std::shared_ptr<WaitState>& wait, NSError* error) {
  {
    std::lock_guard<std::mutex> lock(wait->mutex);
    wait->completed = true;
    if (error != nil) {
      wait->error = "Virtualization.framework operation failed";
    }
  }
  dispatch_semaphore_signal(wait->semaphore);
}

void ExecuteTransition(AsyncOperation* operation) {
  MOPVirtualizationGuestHandle* handle = operation->handle;
  const bool is_start = operation->start;
  const std::string expected_boot_id = operation->expected_boot_id;
  const std::shared_ptr<WaitState> wait = std::make_shared<WaitState>();
  dispatch_async(handle.queue, ^{
    if (handle.closed || handle.machine == nil) {
      {
        std::lock_guard<std::mutex> lock(wait->mutex);
        wait->error = "Virtualization guest VM is closed";
        wait->completed = true;
      }
      dispatch_semaphore_signal(wait->semaphore);
      return;
    }
    if (is_start) {
      if (!handle.machine.canStart) {
        {
          std::lock_guard<std::mutex> lock(wait->mutex);
          wait->error = "Virtualization guest VM cannot start";
          wait->completed = true;
        }
        dispatch_semaphore_signal(wait->semaphore);
        return;
      }
      [handle.machine startWithCompletionHandler:^(NSError* error) {
        if (error == nil && handle.machine.state == VZVirtualMachineStateRunning) {
          handle.bootId = NewBootId();
        }
        {
          std::lock_guard<std::mutex> lock(wait->mutex);
          wait->state = StateName(handle.machine.state);
          if (handle.bootId != nil && handle.bootId.UTF8String != nullptr) wait->boot_id = handle.bootId.UTF8String;
        }
        RecordCompletion(wait, error);
      }];
    } else {
      if (handle.bootId == nil || handle.bootId.UTF8String == nullptr ||
          expected_boot_id != handle.bootId.UTF8String || !handle.machine.canStop) {
        {
          std::lock_guard<std::mutex> lock(wait->mutex);
          wait->error = "Virtualization guest VM stop identity is invalid";
          wait->completed = true;
        }
        dispatch_semaphore_signal(wait->semaphore);
        return;
      }
      [handle.machine stopWithCompletionHandler:^(NSError* error) {
        if (error == nil && handle.machine.state == VZVirtualMachineStateStopped) handle.bootId = nil;
        {
          std::lock_guard<std::mutex> lock(wait->mutex);
          wait->state = StateName(handle.machine.state);
        }
        RecordCompletion(wait, error);
      }];
    }
  });
  const dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(kNativeOperationTimeoutNs));
  if (dispatch_semaphore_wait(wait->semaphore, deadline) != 0) {
    operation->timed_out = true;
    operation->error = "Virtualization guest VM operation exceeded its native deadline";
    return;
  }
  std::lock_guard<std::mutex> lock(wait->mutex);
  if (!wait->error.empty()) {
    operation->error = wait->error;
    return;
  }
  if (is_start && wait->state != "running") {
    operation->error = "Virtualization guest VM did not reach running state";
    return;
  }
  if (!is_start && wait->state != "stopped") {
    operation->error = "Virtualization guest VM did not reach stopped state";
    return;
  }
  if (is_start && !wait->boot_id.empty()) {
    operation->boot_id = wait->boot_id;
  } else if (is_start) {
    operation->error = "Virtualization guest VM boot identity is unavailable";
  }
}

void CompleteTransition(napi_env env, napi_status status, void* data) {
  AsyncOperation* operation = static_cast<AsyncOperation*>(data);
  napi_value result;
  if (status != napi_ok || !operation->error.empty() || operation->timed_out) {
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest VM operation failed" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else {
    napi_create_object(env, &result);
    SetString(env, result, "state", operation->start ? "running" : "stopped");
    SetGuestIdentity(env, result, operation->handle);
    if (operation->start) {
      SetString(env, result, "bootId", operation->boot_id.c_str());
    } else {
      SetString(env, result, "bootId", operation->expected_boot_id.c_str());
    }
    napi_resolve_deferred(env, operation->deferred, result);
  }
  napi_delete_async_work(env, operation->work);
  void* retained = operation->retained_handle;
  operation->handle->magic = kHandleMagic;
  delete operation;
  if (retained != nullptr) {
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)retained;
  }
}

void ExecuteStart(napi_env env, void* data) {
  (void)env;
  ExecuteTransition(static_cast<AsyncOperation*>(data));
}

void ExecuteStop(napi_env env, void* data) {
  (void)env;
  ExecuteTransition(static_cast<AsyncOperation*>(data));
}

void ExecuteStatus(AsyncStatusOperation* operation) {
  MOPVirtualizationGuestHandle* handle = operation->handle;
  const std::shared_ptr<WaitState> wait = std::make_shared<WaitState>();
  dispatch_async(handle.queue, ^{
    if (handle.closed || handle.machine == nil) {
      std::lock_guard<std::mutex> lock(wait->mutex);
      wait->error = "Virtualization guest VM is closed";
      wait->completed = true;
      dispatch_semaphore_signal(wait->semaphore);
      return;
    }
    const VZVirtualMachineState state = handle.machine.state;
    if (state == VZVirtualMachineStateStopped) handle.bootId = nil;
    {
      std::lock_guard<std::mutex> lock(wait->mutex);
      if (state == VZVirtualMachineStateRunning && handle.bootId != nil && handle.bootId.UTF8String != nullptr) {
        wait->state = "running";
        wait->boot_id = handle.bootId.UTF8String;
      } else if (state == VZVirtualMachineStateStopped) {
        wait->state = "stopped";
      } else {
        wait->state = "unknown";
      }
      wait->completed = true;
    }
    dispatch_semaphore_signal(wait->semaphore);
  });
  const dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(kNativeOperationTimeoutNs));
  if (dispatch_semaphore_wait(wait->semaphore, deadline) != 0) {
    operation->timed_out = true;
    operation->error = "Virtualization guest VM status exceeded its native deadline";
    return;
  }
  std::lock_guard<std::mutex> lock(wait->mutex);
  operation->state = wait->state;
  operation->boot_id = wait->boot_id;
  operation->error = wait->error;
}

void CompleteStatus(napi_env env, napi_status status, void* data) {
  AsyncStatusOperation* operation = static_cast<AsyncStatusOperation*>(data);
  if (status != napi_ok || operation->timed_out || !operation->error.empty()) {
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest VM status is unavailable" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else {
    napi_value result;
    napi_create_object(env, &result);
    SetString(env, result, "state", operation->state.empty() ? "unknown" : operation->state.c_str());
    SetGuestIdentity(env, result, operation->handle);
    if (operation->state == "running" && !operation->boot_id.empty()) SetString(env, result, "bootId", operation->boot_id.c_str());
    else SetNull(env, result, "bootId");
    napi_resolve_deferred(env, operation->deferred, result);
  }
  napi_delete_async_work(env, operation->work);
  void* retained = operation->retained_handle;
  delete operation;
  if (retained != nullptr) (void)(__bridge_transfer MOPVirtualizationGuestHandle*)retained;
}

napi_value QueueStatus(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "statusGuestVm requires a handle");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  AsyncStatusOperation* operation = new AsyncStatusOperation();
  operation->env = env;
  operation->handle = handle;
  operation->retained_handle = (__bridge_retained void*)handle;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok) {
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest VM status promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, "virtualization-guest-status", NAPI_AUTO_LENGTH, &resource_name);
  if (napi_create_async_work(env, nullptr, resource_name,
                             [](napi_env worker_env, void* data) {
                               (void)worker_env;
                               ExecuteStatus(static_cast<AsyncStatusOperation*>(data));
                             }, CompleteStatus, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest VM status could not be queued");
    return nullptr;
  }
  return promise;
}

napi_value QueueTransition(napi_env env, napi_callback_info info, bool start) {
  size_t argc = start ? 1 : 2;
  napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != (start ? 1U : 2U)) {
    napi_throw_type_error(env, nullptr, start ? "startGuestVm requires a handle" : "stopGuestVm requires a handle and boot ID");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  std::string expected_boot_id;
  if (!start) {
    char boot_id[256];
    if (!ReadString(env, args[1], boot_id, sizeof(boot_id)) || strlen(boot_id) < 8) {
      napi_throw_type_error(env, nullptr, "Virtualization guest VM boot ID is malformed");
      return nullptr;
    }
    expected_boot_id = boot_id;
  }
  AsyncOperation* operation = new AsyncOperation();
  operation->env = env;
  operation->handle = handle;
  operation->start = start;
  operation->expected_boot_id = expected_boot_id;
  operation->retained_handle = (__bridge_retained void*)handle;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok) {
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest VM promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, start ? "virtualization-guest-start" : "virtualization-guest-stop", NAPI_AUTO_LENGTH, &resource_name);
  const napi_status work_status = napi_create_async_work(
      env, nullptr, resource_name, start ? ExecuteStart : ExecuteStop, CompleteTransition, operation, &operation->work);
  if (work_status != napi_ok || napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest VM operation could not be queued");
    return nullptr;
  }
  return promise;
}

napi_value CreateGuestVm(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value args[5];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 5) {
    napi_throw_type_error(env, nullptr, "createGuestVm requires path, device, inode, sha256, and runtime version");
    return nullptr;
  }
  char image_path[PATH_MAX];
  char expected_device[64];
  char expected_inode[64];
  char expected_digest[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  char runtime_version[129];
  if (!ReadString(env, args[0], image_path, sizeof(image_path)) ||
      !ReadString(env, args[1], expected_device, sizeof(expected_device)) ||
      !ReadString(env, args[2], expected_inode, sizeof(expected_inode)) ||
      !ReadString(env, args[3], expected_digest, sizeof(expected_digest)) ||
      !ReadString(env, args[4], runtime_version, sizeof(runtime_version)) ||
      !IsRuntimeVersion(runtime_version)) {
    napi_throw_type_error(env, nullptr, "Virtualization guest VM identity arguments are malformed");
    return nullptr;
  }
  std::string canonical_path;
  if (!ValidateImage(image_path, expected_device, expected_inode, expected_digest, &canonical_path)) {
    ThrowError(env, "Virtualization guest VM image identity or protection precondition failed");
    return nullptr;
  }

  @autoreleasepool {
    if (!VZVirtualMachine.supported) {
      ThrowError(env, "Virtualization.framework is unavailable on this host");
      return nullptr;
    }
    NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:canonical_path.c_str()]];
    NSError* attachment_error = nil;
    VZDiskImageStorageDeviceAttachment* attachment =
        [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:url readOnly:YES error:&attachment_error];
    if (attachment == nil) {
      ThrowError(env, "Virtualization guest VM image is not an accepted disk image");
      return nullptr;
    }
    VZVirtualMachineConfiguration* configuration = [[VZVirtualMachineConfiguration alloc] init];
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
    configuration.socketDevices = @[
      [[VZVirtioSocketDeviceConfiguration alloc] init]
    ];
    NSError* validation_error = nil;
    if (![configuration validateWithError:&validation_error]) {
      ThrowError(env, "Virtualization guest VM configuration is unavailable");
      return nullptr;
    }
    dispatch_queue_t queue = dispatch_queue_create("com.mac-operator.virtualization-guest", DISPATCH_QUEUE_SERIAL);
    MOPVirtualizationGuestHandle* handle = [[MOPVirtualizationGuestHandle alloc] init];
    handle->magic = kHandleMagic;
    handle.queue = queue;
    handle.machine = [[VZVirtualMachine alloc] initWithConfiguration:configuration queue:queue];
    handle.imagePath = [NSString stringWithUTF8String:canonical_path.c_str()];
    handle.imageSha256 = [NSString stringWithUTF8String:expected_digest];
    handle.runtimeVersion = [NSString stringWithUTF8String:runtime_version];
    handle.bootId = nil;
    handle.closed = NO;
    napi_value result;
    if (napi_create_external(env, (__bridge_retained void*)handle, FinalizeHandle, nullptr, &result) != napi_ok) {
      handle->magic = 0;
      napi_throw_error(env, nullptr, "Virtualization guest VM handle could not be created");
      return nullptr;
    }
    return result;
  }
}

napi_value StartGuestVm(napi_env env, napi_callback_info info) {
  return QueueTransition(env, info, true);
}

napi_value StopGuestVm(napi_env env, napi_callback_info info) {
  return QueueTransition(env, info, false);
}

napi_value StatusGuestVm(napi_env env, napi_callback_info info) {
  return QueueStatus(env, info);
}

napi_value CloseGuestVm(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "closeGuestVm requires a handle");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  __block bool rejected = false;
  dispatch_sync(handle.queue, ^{
    if (handle.closed) return;
    if (handle.machine == nil || handle.machine.state != VZVirtualMachineStateStopped) {
      rejected = true;
      return;
    }
    handle.closed = YES;
    handle->magic = 0;
    handle.machine = nil;
    handle.queue = nil;
  });
  if (rejected) {
    ThrowError(env, "Virtualization guest VM must be stopped before close");
    return nullptr;
  }
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

void SetFunction(napi_env env, napi_value exports, const char* name, napi_callback callback) {
  napi_value function;
  napi_create_function(env, name, NAPI_AUTO_LENGTH, callback, nullptr, &function);
  napi_set_named_property(env, exports, name, function);
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value version;
  napi_create_uint32(env, NAPI_VERSION, &version);
  napi_set_named_property(env, exports, "nativeNapiVersion", version);
  SetFunction(env, exports, "createGuestVm", CreateGuestVm);
  SetFunction(env, exports, "startGuestVm", StartGuestVm);
  SetFunction(env, exports, "stopGuestVm", StopGuestVm);
  SetFunction(env, exports, "statusGuestVm", StatusGuestVm);
  SetFunction(env, exports, "closeGuestVm", CloseGuestVm);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
