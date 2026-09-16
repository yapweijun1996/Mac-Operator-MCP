#include <node_api.h>
#include <node_version.h>

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <time.h>
#include <unordered_set>
#include <unistd.h>
#include <vector>

constexpr uint64_t kGuestConnectionMagic = 0x4d4f504753545243ULL;

struct GuestListenerState {
  std::mutex mutex;
  std::condition_variable condition;
  std::deque<void*> pending_connections;
  size_t max_connections = 1;
  bool closed = false;

  ~GuestListenerState() {
    for (void* retained_connection : pending_connections) {
      if (retained_connection != nullptr) {
        (void)(__bridge_transfer VZVirtioSocketConnection*)retained_connection;
      }
    }
  }
};

struct GuestConnectionHandle {
  uint64_t magic = kGuestConnectionMagic;
  void* retained_connection = nullptr;
  int file_descriptor = -1;
  std::mutex mutex;
  bool closed = false;
};

@interface MOPVirtioSocketListenerDelegate : NSObject <VZVirtioSocketListenerDelegate> {
@public
  std::shared_ptr<GuestListenerState> state;
}
- (instancetype)initWithState:(std::shared_ptr<GuestListenerState>)listenerState;
@end

@interface MOPVirtualizationGuestHandle : NSObject {
@public
  std::atomic<uint64_t> magic;
  std::mutex listener_mutex;
  std::unordered_map<uint32_t, std::shared_ptr<GuestListenerState>> listener_states;
  // Broker-owned exchanges are tracked so stop/close can interrupt guest I/O.
  std::mutex connection_mutex;
  std::unordered_set<void*> active_connections;
  std::atomic<bool> closed_atomic;
}
@property(nonatomic, strong) VZVirtualMachine* machine;
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, VZVirtioSocketListener*>* listeners;
@property(nonatomic, strong) NSMutableDictionary<NSNumber*, MOPVirtioSocketListenerDelegate*>* listenerDelegates;
@property(nonatomic, copy) NSString* imagePath;
@property(nonatomic, copy) NSString* imageSha256;
@property(nonatomic, copy) NSString* runtimeVersion;
@property(nonatomic, copy) NSString* bootId;
@property(nonatomic, assign) BOOL closed;
@end

@implementation MOPVirtualizationGuestHandle
@end

@implementation MOPVirtioSocketListenerDelegate

- (instancetype)initWithState:(std::shared_ptr<GuestListenerState>)listenerState {
  self = [super init];
  if (self != nil) state = std::move(listenerState);
  return self;
}

- (BOOL)listener:(VZVirtioSocketListener*)listener
    shouldAcceptNewConnection:(VZVirtioSocketConnection*)connection
    fromSocketDevice:(VZVirtioSocketDevice*)socketDevice {
  (void)listener;
  (void)socketDevice;
  if (connection == nil || connection.fileDescriptor < 0 || state == nullptr) return NO;
  std::lock_guard<std::mutex> lock(state->mutex);
  if (state->closed || state->pending_connections.size() >= state->max_connections) return NO;
  state->pending_connections.push_back((__bridge_retained void*)connection);
  state->condition.notify_one();
  return YES;
}

@end

namespace {

#if defined(__arm64__) || defined(__aarch64__)
constexpr const char* kNativeArch = "arm64";
#elif defined(__x86_64__)
constexpr const char* kNativeArch = "x64";
#else
constexpr const char* kNativeArch = "unknown";
#endif
constexpr const char* kNativePlatform = "darwin";

constexpr uint64_t kMaxImageBytes = 512ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr size_t kDigestChunkBytes = 1024 * 1024;
constexpr uint64_t kHandleMagic = 0x4d4f50565a4c4946ULL;
constexpr uint64_t kNativeOperationTimeoutNs = 15ULL * 60ULL * 1000000000ULL;
constexpr size_t kMaxFrameBytes = 4 * 1024 * 1024;
constexpr uint32_t kMinVsockPort = 1;
constexpr uint32_t kMaxVsockPort = 65535;

void CloseActiveVirtioConnections(MOPVirtualizationGuestHandle* handle);

void ReleaseRetainedConnection(void* retained_connection) {
  if (retained_connection != nullptr) {
    (void)(__bridge_transfer VZVirtioSocketConnection*)retained_connection;
  }
}

void CloseListenerState(const std::shared_ptr<GuestListenerState>& state) {
  if (state == nullptr) return;
  std::deque<void*> pending;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    state->closed = true;
    pending.swap(state->pending_connections);
  }
  state->condition.notify_all();
  for (void* retained_connection : pending) ReleaseRetainedConnection(retained_connection);
}

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

bool IsSystemPublishedImage(const char* canonical_path, const struct stat& path_stat) {
  // The Virtualization.framework image attachment accepts a pathname, not an
  // already-open descriptor. Require a root-owned publication boundary so an
  // unprivileged process cannot replace the image between our descriptor
  // readback and initWithURL:. Root may still rotate the artifact, but that is
  // an explicit host administration action and is detected by later readback.
  if (!S_ISREG(path_stat.st_mode) || path_stat.st_uid != 0 ||
      (path_stat.st_mode & 0022) != 0 || (path_stat.st_mode & 0444) == 0) {
    return false;
  }
  char parent_path[PATH_MAX];
  if (strlcpy(parent_path, canonical_path, sizeof(parent_path)) >= sizeof(parent_path)) return false;
  char* separator = strrchr(parent_path, '/');
  if (separator == nullptr) return false;
  if (separator == parent_path) parent_path[1] = '\0';
  else *separator = '\0';
  for (;;) {
    struct stat parent_stat{};
    if (lstat(parent_path, &parent_stat) != 0 || !S_ISDIR(parent_stat.st_mode) ||
        parent_stat.st_uid != 0 || (parent_stat.st_mode & 0022) != 0) {
      return false;
    }
    if (strcmp(parent_path, "/") == 0) break;
    separator = strrchr(parent_path, '/');
    if (separator == nullptr) return false;
    if (separator == parent_path) parent_path[1] = '\0';
    else *separator = '\0';
  }
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
      current_uid == 0 || current_uid == static_cast<uid_t>(-1) ||
      !IsSystemPublishedImage(resolved_path, path_stat) ||
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
  if (handle->magic.load(std::memory_order_acquire) != kHandleMagic) {
    napi_throw_type_error(env, nullptr, "Virtualization guest VM handle is invalid");
    return nullptr;
  }
  return handle;
}

GuestConnectionHandle* ReadConnectionHandle(napi_env env, napi_value value) {
  void* data = nullptr;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == nullptr) {
    napi_throw_type_error(env, nullptr, "Virtualization guest connection handle is invalid");
    return nullptr;
  }
  GuestConnectionHandle* connection = static_cast<GuestConnectionHandle*>(data);
  if (connection->magic != kGuestConnectionMagic) {
    napi_throw_type_error(env, nullptr, "Virtualization guest connection handle is invalid");
    return nullptr;
  }
  return connection;
}

void CloseConnectionHandle(GuestConnectionHandle* connection) {
  if (connection == nullptr) return;
  std::lock_guard<std::mutex> lock(connection->mutex);
  if (connection->closed) return;
  connection->closed = true;
  if (connection->retained_connection != nullptr) {
    VZVirtioSocketConnection* native_connection =
        (__bridge VZVirtioSocketConnection*)connection->retained_connection;
    [native_connection close];
  }
}

void FinalizeConnection(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  GuestConnectionHandle* connection = static_cast<GuestConnectionHandle*>(data);
  if (connection == nullptr) return;
  CloseConnectionHandle(connection);
  connection->magic = 0;
  if (connection->retained_connection != nullptr) {
    (void)(__bridge_transfer VZVirtioSocketConnection*)connection->retained_connection;
    connection->retained_connection = nullptr;
  }
  delete connection;
}

void CloseAllListeners(MOPVirtualizationGuestHandle* handle) {
  if (handle == nullptr) return;
  std::unordered_map<uint32_t, std::shared_ptr<GuestListenerState>> states;
  {
    std::lock_guard<std::mutex> lock(handle->listener_mutex);
    states.swap(handle->listener_states);
  }
  if (handle.queue != nil) {
    dispatch_sync(handle.queue, ^{
      if (handle.machine != nil) {
        NSArray<VZSocketDevice*>* devices = handle.machine.socketDevices;
        VZVirtioSocketDevice* socket_device = devices.count == 1 &&
            [devices.firstObject isKindOfClass:[VZVirtioSocketDevice class]]
            ? (VZVirtioSocketDevice*)devices.firstObject : nil;
        if (socket_device != nil) {
          for (const auto& entry : states) [socket_device removeSocketListenerForPort:entry.first];
        }
      }
      [handle.listeners removeAllObjects];
      [handle.listenerDelegates removeAllObjects];
    });
  }
  for (const auto& entry : states) CloseListenerState(entry.second);
}

void FinalizeHandle(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  if (data != nullptr) {
    MOPVirtualizationGuestHandle* handle = (__bridge_transfer MOPVirtualizationGuestHandle*)data;
    handle->closed_atomic.store(true, std::memory_order_release);
    CloseActiveVirtioConnections(handle);
    CloseAllListeners(handle);
    handle->magic.store(0, std::memory_order_release);
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

struct ChannelState {
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  std::mutex mutex;
  void* retained_connection = nullptr;
  int file_descriptor = -1;
  bool abandoned = false;
  bool completed = false;
  std::string error;
  std::vector<unsigned char> response;
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

struct AsyncChannelOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  void* retained_handle = nullptr;
  MOPVirtualizationGuestHandle* handle = nullptr;
  uint32_t port = 0;
  uint32_t timeout_ms = 0;
  size_t max_response_bytes = 0;
  std::vector<unsigned char> request;
  std::vector<unsigned char> response;
  std::string error;
  bool timed_out = false;
};

struct AsyncAcceptOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  std::shared_ptr<GuestListenerState> state;
  uint32_t timeout_ms = 0;
  void* retained_connection = nullptr;
  bool timed_out = false;
  std::string error;
};

struct AsyncConnectionReadOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  napi_ref connection_reference = nullptr;
  GuestConnectionHandle* connection = nullptr;
  uint32_t max_bytes = 0;
  uint32_t timeout_ms = 0;
  bool eof = false;
  bool timed_out = false;
  std::string error;
  std::vector<unsigned char> response;
};

struct AsyncConnectionWriteOperation {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  napi_ref connection_reference = nullptr;
  GuestConnectionHandle* connection = nullptr;
  uint32_t timeout_ms = 0;
  std::vector<unsigned char> request;
  bool timed_out = false;
  std::string error;
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

uint64_t MonotonicMilliseconds() {
  struct timespec time_value{};
  if (clock_gettime(CLOCK_MONOTONIC, &time_value) != 0) return 0;
  return static_cast<uint64_t>(time_value.tv_sec) * 1000ULL +
      static_cast<uint64_t>(time_value.tv_nsec) / 1000000ULL;
}

int RemainingMilliseconds(uint64_t deadline_ms) {
  const uint64_t now_ms = MonotonicMilliseconds();
  if (now_ms == 0 || now_ms >= deadline_ms) return 0;
  const uint64_t remaining = deadline_ms - now_ms;
  return remaining > static_cast<uint64_t>(INT_MAX) ? INT_MAX : static_cast<int>(remaining);
}

bool WaitForSocket(int descriptor, short events, uint64_t deadline_ms) {
  struct pollfd poll_descriptor{};
  poll_descriptor.fd = descriptor;
  poll_descriptor.events = events;
  while (true) {
    const int remaining_ms = RemainingMilliseconds(deadline_ms);
    if (remaining_ms < 1) return false;
    const int result = poll(&poll_descriptor, 1, remaining_ms);
    if (result > 0 && (poll_descriptor.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return (poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
    }
    if (result == 0) return false;
    if (result < 0 && errno == EINTR) continue;
    return false;
  }
}

bool WriteAll(int descriptor, const unsigned char* bytes, size_t length, uint64_t deadline_ms) {
  size_t offset = 0;
  while (offset < length) {
    if (!WaitForSocket(descriptor, POLLOUT, deadline_ms)) return false;
    const ssize_t written = send(descriptor, bytes + offset, length - offset, MSG_NOSIGNAL);
    if (written > 0) {
      offset += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    return false;
  }
  return true;
}

bool ReadAll(int descriptor, unsigned char* bytes, size_t length, uint64_t deadline_ms) {
  size_t offset = 0;
  while (offset < length) {
    if (!WaitForSocket(descriptor, POLLIN, deadline_ms)) return false;
    const ssize_t received = recv(descriptor, bytes + offset, length - offset, 0);
    if (received > 0) {
      offset += static_cast<size_t>(received);
      continue;
    }
    if (received < 0 && errno == EINTR) continue;
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    return false;
  }
  return true;
}

bool IsGuestPort(uint32_t port) {
  return port >= kMinVsockPort && port <= kMaxVsockPort;
}

VZVirtioSocketDevice* SocketDeviceForHandle(MOPVirtualizationGuestHandle* handle) {
  if (handle == nullptr || handle.machine == nil) return nil;
  NSArray<VZSocketDevice*>* devices = handle.machine.socketDevices;
  if (devices.count != 1 || ![devices.firstObject isKindOfClass:[VZVirtioSocketDevice class]]) return nil;
  return (VZVirtioSocketDevice*)devices.firstObject;
}

void ExecuteAccept(AsyncAcceptOperation* operation) {
  if (operation->state == nullptr) {
    operation->error = "Virtualization guest listener is unavailable";
    return;
  }
  std::unique_lock<std::mutex> lock(operation->state->mutex);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(operation->timeout_ms);
  while (!operation->state->closed && operation->state->pending_connections.empty()) {
    if (operation->state->condition.wait_until(lock, deadline) == std::cv_status::timeout) {
      operation->timed_out = true;
      return;
    }
  }
  if (!operation->state->pending_connections.empty()) {
    operation->retained_connection = operation->state->pending_connections.front();
    operation->state->pending_connections.pop_front();
    return;
  }
  if (operation->state->closed) {
    operation->error = "Virtualization guest listener is closed";
    return;
  }
  operation->timed_out = true;
}

void CompleteAccept(napi_env env, napi_status status, void* data) {
  AsyncAcceptOperation* operation = static_cast<AsyncAcceptOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    ReleaseRetainedConnection(operation->retained_connection);
    operation->retained_connection = nullptr;
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest connection accept failed" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else if (operation->timed_out || operation->retained_connection == nullptr) {
    napi_value result;
    napi_get_null(env, &result);
    napi_resolve_deferred(env, operation->deferred, result);
  } else {
    GuestConnectionHandle* connection = new GuestConnectionHandle();
    connection->retained_connection = operation->retained_connection;
    operation->retained_connection = nullptr;
    VZVirtioSocketConnection* native_connection =
        (__bridge VZVirtioSocketConnection*)connection->retained_connection;
    connection->file_descriptor = native_connection == nil ? -1 : native_connection.fileDescriptor;
    napi_value result;
    const bool external_created = connection->file_descriptor >= 0 &&
        napi_create_external(env, connection, FinalizeConnection, nullptr, &result) == napi_ok;
    if (!external_created) {
      if (connection->retained_connection != nullptr) {
        (void)(__bridge_transfer VZVirtioSocketConnection*)connection->retained_connection;
        connection->retained_connection = nullptr;
      }
      delete connection;
      napi_value error;
      napi_create_string_utf8(env, "Virtualization guest connection handle could not be created", NAPI_AUTO_LENGTH, &error);
      napi_reject_deferred(env, operation->deferred, error);
    } else {
      napi_resolve_deferred(env, operation->deferred, result);
    }
  }
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value ListenGuestPort(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3) {
    napi_throw_type_error(env, nullptr, "listenGuestPort requires a handle, port, and connection cap");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  uint32_t port = 0;
  uint32_t max_connections = 0;
  if (napi_get_value_uint32(env, args[1], &port) != napi_ok ||
      napi_get_value_uint32(env, args[2], &max_connections) != napi_ok ||
      !IsGuestPort(port) || max_connections < 1 || max_connections > 8) {
    napi_throw_range_error(env, nullptr, "Virtualization guest listener limits are invalid");
    return nullptr;
  }
  auto state = std::make_shared<GuestListenerState>();
  state->max_connections = max_connections;
  __block bool failed = false;
  dispatch_sync(handle.queue, ^{
    if (handle.closed || handle.machine == nil || SocketDeviceForHandle(handle) == nil) {
      failed = true;
      return;
    }
    VZVirtioSocketDevice* socket_device = SocketDeviceForHandle(handle);
    if (socket_device == nil) {
      failed = true;
      return;
    }
    std::shared_ptr<GuestListenerState> replaced;
    {
      std::lock_guard<std::mutex> lock(handle->listener_mutex);
      const auto previous = handle->listener_states.find(port);
      if (previous != handle->listener_states.end()) {
        replaced = previous->second;
        handle->listener_states.erase(previous);
      }
      handle->listener_states.emplace(port, state);
    }
    if (replaced != nullptr) CloseListenerState(replaced);
    MOPVirtioSocketListenerDelegate* delegate = [[MOPVirtioSocketListenerDelegate alloc] initWithState:state];
    VZVirtioSocketListener* listener = [[VZVirtioSocketListener alloc] init];
    listener.delegate = delegate;
    [socket_device setSocketListener:listener forPort:port];
    handle.listeners[@(port)] = listener;
    handle.listenerDelegates[@(port)] = delegate;
  });
  if (failed) {
    CloseListenerState(state);
    napi_throw_error(env, nullptr, "Virtualization guest virtio socket listener is unavailable");
    return nullptr;
  }
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value RemoveGuestPort(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2) {
    napi_throw_type_error(env, nullptr, "removeGuestPort requires a handle and port");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  uint32_t port = 0;
  if (napi_get_value_uint32(env, args[1], &port) != napi_ok || !IsGuestPort(port)) {
    napi_throw_range_error(env, nullptr, "Virtualization guest listener port is invalid");
    return nullptr;
  }
  std::shared_ptr<GuestListenerState> state;
  {
    std::lock_guard<std::mutex> lock(handle->listener_mutex);
    const auto found = handle->listener_states.find(port);
    if (found != handle->listener_states.end()) {
      state = found->second;
      handle->listener_states.erase(found);
    }
  }
  dispatch_sync(handle.queue, ^{
    VZVirtioSocketDevice* socket_device = SocketDeviceForHandle(handle);
    if (socket_device != nil) [socket_device removeSocketListenerForPort:port];
    [handle.listeners removeObjectForKey:@(port)];
    [handle.listenerDelegates removeObjectForKey:@(port)];
  });
  CloseListenerState(state);
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value AcceptGuestConnection(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3) {
    napi_throw_type_error(env, nullptr, "acceptGuestConnection requires a handle, port, and timeout");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  uint32_t port = 0;
  uint32_t timeout_ms = 0;
  if (napi_get_value_uint32(env, args[1], &port) != napi_ok ||
      napi_get_value_uint32(env, args[2], &timeout_ms) != napi_ok ||
      !IsGuestPort(port) || timeout_ms < 1 || timeout_ms > 120000) {
    napi_throw_range_error(env, nullptr, "Virtualization guest accept limits are invalid");
    return nullptr;
  }
  std::shared_ptr<GuestListenerState> state;
  {
    std::lock_guard<std::mutex> lock(handle->listener_mutex);
    const auto found = handle->listener_states.find(port);
    if (found != handle->listener_states.end()) state = found->second;
  }
  if (state == nullptr) {
    napi_throw_error(env, nullptr, "Virtualization guest listener is not configured");
    return nullptr;
  }
  AsyncAcceptOperation* operation = new AsyncAcceptOperation();
  operation->env = env;
  operation->state = std::move(state);
  operation->timeout_ms = timeout_ms;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok) {
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest accept promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, "virtualization-guest-accept", NAPI_AUTO_LENGTH, &resource_name);
  if (napi_create_async_work(env, nullptr, resource_name,
                             [](napi_env worker_env, void* data) {
                               (void)worker_env;
                               ExecuteAccept(static_cast<AsyncAcceptOperation*>(data));
                             }, CompleteAccept, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest accept could not be queued");
    return nullptr;
  }
  return promise;
}

void ExecuteConnectionRead(AsyncConnectionReadOperation* operation) {
  if (operation->connection == nullptr) {
    operation->error = "Virtualization guest connection is unavailable";
    return;
  }
  int descriptor = -1;
  {
    std::lock_guard<std::mutex> lock(operation->connection->mutex);
    if (operation->connection->closed || operation->connection->retained_connection == nullptr) {
      operation->eof = true;
      return;
    }
    descriptor = operation->connection->file_descriptor;
  }
  if (descriptor < 0) {
    operation->eof = true;
    return;
  }
  const uint64_t start_ms = MonotonicMilliseconds();
  const uint64_t deadline_ms = start_ms == 0 ? 0 : start_ms + operation->timeout_ms;
  if (deadline_ms == 0) {
    operation->error = "Virtualization guest connection clock is unavailable";
    return;
  }
  operation->response.resize(operation->max_bytes);
  while (true) {
    struct pollfd poll_descriptor{};
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN;
    const int remaining_ms = RemainingMilliseconds(deadline_ms);
    if (remaining_ms < 1) {
      operation->timed_out = true;
      operation->response.clear();
      return;
    }
    const int polled = poll(&poll_descriptor, 1, remaining_ms);
    if (polled == 0) {
      operation->timed_out = true;
      operation->response.clear();
      return;
    }
    if (polled < 0 && errno == EINTR) continue;
    if (polled < 0 || (poll_descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
      operation->error = "Virtualization guest connection read failed";
      operation->response.clear();
      return;
    }
    const ssize_t received = recv(descriptor, operation->response.data(), operation->response.size(), MSG_DONTWAIT);
    if (received > 0) {
      operation->response.resize(static_cast<size_t>(received));
      return;
    }
    if (received == 0) {
      operation->eof = true;
      operation->response.clear();
      return;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
    operation->error = "Virtualization guest connection read failed";
    operation->response.clear();
    return;
  }
}

void CompleteConnectionRead(napi_env env, napi_status status, void* data) {
  AsyncConnectionReadOperation* operation = static_cast<AsyncConnectionReadOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest connection read failed" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else if (operation->timed_out) {
    napi_value error;
    napi_create_string_utf8(env, "Virtualization guest connection read timed out", NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else if (operation->eof) {
    napi_value result;
    napi_get_null(env, &result);
    napi_resolve_deferred(env, operation->deferred, result);
  } else {
    napi_value result;
    napi_create_buffer_copy(env, operation->response.size(), operation->response.data(), nullptr, &result);
    napi_resolve_deferred(env, operation->deferred, result);
  }
  if (operation->connection_reference != nullptr) napi_delete_reference(env, operation->connection_reference);
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value ReadGuestConnectionChunk(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3) {
    napi_throw_type_error(env, nullptr, "readGuestConnectionChunk requires a connection, byte cap, and timeout");
    return nullptr;
  }
  GuestConnectionHandle* connection = ReadConnectionHandle(env, args[0]);
  if (connection == nullptr) return nullptr;
  uint32_t max_bytes = 0;
  uint32_t timeout_ms = 0;
  if (napi_get_value_uint32(env, args[1], &max_bytes) != napi_ok ||
      napi_get_value_uint32(env, args[2], &timeout_ms) != napi_ok ||
      max_bytes < 1 || max_bytes > kMaxFrameBytes || timeout_ms < 1 || timeout_ms > 120000) {
    napi_throw_range_error(env, nullptr, "Virtualization guest connection read limits are invalid");
    return nullptr;
  }
  AsyncConnectionReadOperation* operation = new AsyncConnectionReadOperation();
  operation->env = env;
  operation->connection = connection;
  operation->max_bytes = max_bytes;
  operation->timeout_ms = timeout_ms;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok ||
      napi_create_reference(env, args[0], 1, &operation->connection_reference) != napi_ok) {
    if (operation->connection_reference != nullptr) napi_delete_reference(env, operation->connection_reference);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest connection read promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, "virtualization-guest-connection-read", NAPI_AUTO_LENGTH, &resource_name);
  if (napi_create_async_work(env, nullptr, resource_name,
                             [](napi_env worker_env, void* data) {
                               (void)worker_env;
                               ExecuteConnectionRead(static_cast<AsyncConnectionReadOperation*>(data));
                             }, CompleteConnectionRead, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    napi_delete_reference(env, operation->connection_reference);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest connection read could not be queued");
    return nullptr;
  }
  return promise;
}

void ExecuteConnectionWrite(AsyncConnectionWriteOperation* operation) {
  if (operation->connection == nullptr) {
    operation->error = "Virtualization guest connection is unavailable";
    return;
  }
  int descriptor = -1;
  {
    std::lock_guard<std::mutex> lock(operation->connection->mutex);
    if (operation->connection->closed || operation->connection->retained_connection == nullptr) {
      operation->error = "Virtualization guest connection is closed";
      return;
    }
    descriptor = operation->connection->file_descriptor;
  }
  const uint64_t start_ms = MonotonicMilliseconds();
  const uint64_t deadline_ms = start_ms == 0 ? 0 : start_ms + operation->timeout_ms;
  if (descriptor < 0 || deadline_ms == 0 ||
      !WriteAll(descriptor, operation->request.data(), operation->request.size(), deadline_ms)) {
    operation->timed_out = deadline_ms != 0 && RemainingMilliseconds(deadline_ms) < 1;
    operation->error = operation->timed_out
        ? "Virtualization guest connection write timed out"
        : "Virtualization guest connection write failed";
  }
}

void CompleteConnectionWrite(napi_env env, napi_status status, void* data) {
  AsyncConnectionWriteOperation* operation = static_cast<AsyncConnectionWriteOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest connection write failed" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_resolve_deferred(env, operation->deferred, undefined);
  }
  if (operation->connection_reference != nullptr) napi_delete_reference(env, operation->connection_reference);
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value WriteGuestConnectionChunk(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3) {
    napi_throw_type_error(env, nullptr, "writeGuestConnectionChunk requires a connection, frame, and timeout");
    return nullptr;
  }
  GuestConnectionHandle* connection = ReadConnectionHandle(env, args[0]);
  if (connection == nullptr) return nullptr;
  bool is_buffer = false;
  napi_is_buffer(env, args[1], &is_buffer);
  uint32_t timeout_ms = 0;
  if (!is_buffer || napi_get_value_uint32(env, args[2], &timeout_ms) != napi_ok || timeout_ms < 1 || timeout_ms > 120000) {
    napi_throw_range_error(env, nullptr, "Virtualization guest connection write limits are invalid");
    return nullptr;
  }
  void* data = nullptr;
  size_t length = 0;
  if (napi_get_buffer_info(env, args[1], &data, &length) != napi_ok ||
      data == nullptr || length < 1 || length > kMaxFrameBytes) {
    napi_throw_range_error(env, nullptr, "Virtualization guest connection frame exceeds the byte limit");
    return nullptr;
  }
  AsyncConnectionWriteOperation* operation = new AsyncConnectionWriteOperation();
  operation->env = env;
  operation->connection = connection;
  operation->timeout_ms = timeout_ms;
  operation->request.assign(static_cast<unsigned char*>(data), static_cast<unsigned char*>(data) + length);
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok ||
      napi_create_reference(env, args[0], 1, &operation->connection_reference) != napi_ok) {
    if (operation->connection_reference != nullptr) napi_delete_reference(env, operation->connection_reference);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest connection write promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, "virtualization-guest-connection-write", NAPI_AUTO_LENGTH, &resource_name);
  if (napi_create_async_work(env, nullptr, resource_name,
                             [](napi_env worker_env, void* data) {
                               (void)worker_env;
                               ExecuteConnectionWrite(static_cast<AsyncConnectionWriteOperation*>(data));
                             }, CompleteConnectionWrite, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    napi_delete_reference(env, operation->connection_reference);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest connection write could not be queued");
    return nullptr;
  }
  return promise;
}

napi_value CloseGuestConnection(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "closeGuestConnection requires a connection");
    return nullptr;
  }
  GuestConnectionHandle* connection = ReadConnectionHandle(env, args[0]);
  if (connection == nullptr) return nullptr;
  CloseConnectionHandle(connection);
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

uint32_t ReadBigEndian32(const unsigned char* bytes) {
  return (static_cast<uint32_t>(bytes[0]) << 24) |
      (static_cast<uint32_t>(bytes[1]) << 16) |
      (static_cast<uint32_t>(bytes[2]) << 8) |
      static_cast<uint32_t>(bytes[3]);
}

void WriteBigEndian32(unsigned char* bytes, uint32_t value) {
  bytes[0] = static_cast<unsigned char>((value >> 24) & 0xff);
  bytes[1] = static_cast<unsigned char>((value >> 16) & 0xff);
  bytes[2] = static_cast<unsigned char>((value >> 8) & 0xff);
  bytes[3] = static_cast<unsigned char>(value & 0xff);
}

void ReleaseVirtioConnection(void* retained_connection) {
  if (retained_connection != nullptr) {
    (void)(__bridge_transfer VZVirtioSocketConnection*)retained_connection;
  }
}

bool TrackVirtioConnection(MOPVirtualizationGuestHandle* handle, void* retained_connection) {
  if (handle == nullptr || retained_connection == nullptr) return false;
  bool close_immediately = false;
  {
    std::lock_guard<std::mutex> lock(handle->connection_mutex);
    if (handle->closed_atomic.load(std::memory_order_acquire)) {
      close_immediately = true;
    } else {
      handle->active_connections.insert(retained_connection);
    }
  }
  if (close_immediately) {
    VZVirtioSocketConnection* connection =
        (__bridge VZVirtioSocketConnection*)retained_connection;
    if (connection != nil) [connection close];
    return false;
  }
  return true;
}

void ReleaseTrackedVirtioConnection(MOPVirtualizationGuestHandle* handle, void* retained_connection) {
  if (retained_connection == nullptr) return;
  if (handle != nullptr) {
    std::lock_guard<std::mutex> lock(handle->connection_mutex);
    handle->active_connections.erase(retained_connection);
  }
  ReleaseVirtioConnection(retained_connection);
}

void CloseActiveVirtioConnections(MOPVirtualizationGuestHandle* handle) {
  if (handle == nullptr) return;
  std::vector<void*> retained_connections;
  {
    std::lock_guard<std::mutex> lock(handle->connection_mutex);
    retained_connections.reserve(handle->active_connections.size());
    for (void* active_connection : handle->active_connections) {
      VZVirtioSocketConnection* connection =
          (__bridge VZVirtioSocketConnection*)active_connection;
      if (connection != nil) retained_connections.push_back((__bridge_retained void*)connection);
    }
  }
  for (void* retained_connection : retained_connections) {
    VZVirtioSocketConnection* connection =
        (__bridge VZVirtioSocketConnection*)retained_connection;
    if (connection != nil) [connection close];
    ReleaseVirtioConnection(retained_connection);
  }
}

void ExecuteChannel(AsyncChannelOperation* operation) {
  MOPVirtualizationGuestHandle* handle = operation->handle;
  const uint32_t port = operation->port;
  const uint32_t timeout_ms = operation->timeout_ms;
  const size_t max_response_bytes = operation->max_response_bytes;
  const std::vector<unsigned char> request = operation->request;
  const std::shared_ptr<ChannelState> channel = std::make_shared<ChannelState>();
  dispatch_async(handle.queue, ^{
    if (handle.closed || handle.machine == nil || handle.machine.state != VZVirtualMachineStateRunning) {
      std::lock_guard<std::mutex> lock(channel->mutex);
      channel->error = "Virtualization guest VM is not running";
      channel->completed = true;
      dispatch_semaphore_signal(channel->semaphore);
      return;
    }
    NSArray<VZSocketDevice*>* devices = handle.machine.socketDevices;
    VZVirtioSocketDevice* socket_device = devices.count == 1 &&
        [devices.firstObject isKindOfClass:[VZVirtioSocketDevice class]]
        ? (VZVirtioSocketDevice*)devices.firstObject : nil;
    if (socket_device == nil) {
      std::lock_guard<std::mutex> lock(channel->mutex);
      channel->error = "Virtualization guest virtio socket device is unavailable";
      channel->completed = true;
      dispatch_semaphore_signal(channel->semaphore);
      return;
    }
    [socket_device connectToPort:port completionHandler:^(VZVirtioSocketConnection* connection, NSError* error) {
      void* retained_connection = connection == nil ? nullptr : (__bridge_retained void*)connection;
      bool release_connection = false;
      {
        std::lock_guard<std::mutex> lock(channel->mutex);
        if (channel->abandoned) {
          release_connection = retained_connection != nullptr;
        } else if (error != nil || retained_connection == nullptr || connection.fileDescriptor < 0) {
          release_connection = retained_connection != nullptr;
          channel->error = "Virtualization guest virtio socket connection failed";
          channel->completed = true;
        } else if (!TrackVirtioConnection(handle, retained_connection)) {
          release_connection = true;
          channel->error = "Virtualization guest VM is closed";
          channel->completed = true;
        } else {
          channel->retained_connection = retained_connection;
          channel->file_descriptor = connection.fileDescriptor;
          channel->completed = true;
        }
      }
      if (release_connection) ReleaseVirtioConnection(retained_connection);
      dispatch_semaphore_signal(channel->semaphore);
    }];
  });

  const uint64_t start_ms = MonotonicMilliseconds();
  const uint64_t deadline_ms = start_ms == 0 ? 0 : start_ms + timeout_ms;
  if (deadline_ms == 0 || dispatch_semaphore_wait(channel->semaphore,
      dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(timeout_ms) * 1000000LL)) != 0) {
    void* abandoned_connection = nullptr;
    {
      std::lock_guard<std::mutex> lock(channel->mutex);
      channel->abandoned = true;
      abandoned_connection = channel->retained_connection;
      channel->retained_connection = nullptr;
    }
    ReleaseTrackedVirtioConnection(handle, abandoned_connection);
    operation->timed_out = true;
    operation->error = "Virtualization guest virtio socket connection timed out";
    return;
  }

  void* retained_connection = nullptr;
  int descriptor = -1;
  {
    std::lock_guard<std::mutex> lock(channel->mutex);
    if (!channel->error.empty()) {
      operation->error = channel->error;
      return;
    }
    retained_connection = channel->retained_connection;
    descriptor = channel->file_descriptor;
  }
  if (descriptor < 0 || retained_connection == nullptr) {
    operation->error = "Virtualization guest virtio socket connection is unavailable";
    return;
  }
  int no_sigpipe = 1;
  (void)setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
  std::vector<unsigned char> request_frame(4 + request.size());
  WriteBigEndian32(request_frame.data(), static_cast<uint32_t>(request.size()));
  std::copy(request.begin(), request.end(), request_frame.begin() + 4);
  if (!WriteAll(descriptor, request_frame.data(), request_frame.size(), deadline_ms)) {
    operation->error = "Virtualization guest virtio socket request failed";
    ReleaseTrackedVirtioConnection(handle, retained_connection);
    return;
  }
  unsigned char response_header[4];
  if (!ReadAll(descriptor, response_header, sizeof(response_header), deadline_ms)) {
    operation->error = "Virtualization guest virtio socket response was unavailable";
    ReleaseTrackedVirtioConnection(handle, retained_connection);
    return;
  }
  const uint32_t response_bytes = ReadBigEndian32(response_header);
  if (response_bytes < 1 || response_bytes > max_response_bytes) {
    operation->error = "Virtualization guest response frame exceeded the byte limit";
    ReleaseTrackedVirtioConnection(handle, retained_connection);
    return;
  }
  operation->response.resize(response_bytes);
  if (!ReadAll(descriptor, operation->response.data(), operation->response.size(), deadline_ms)) {
    operation->error = "Virtualization guest virtio socket response was truncated";
    operation->response.clear();
    ReleaseTrackedVirtioConnection(handle, retained_connection);
    return;
  }
  struct pollfd trailing{};
  trailing.fd = descriptor;
  trailing.events = POLLIN;
  if (poll(&trailing, 1, 0) > 0 && (trailing.revents & POLLIN) != 0) {
    operation->error = "Virtualization guest response contained trailing frame data";
    operation->response.clear();
  }
  ReleaseTrackedVirtioConnection(handle, retained_connection);
}

void CompleteChannel(napi_env env, napi_status status, void* data) {
  AsyncChannelOperation* operation = static_cast<AsyncChannelOperation*>(data);
  if (status != napi_ok || operation->timed_out || !operation->error.empty()) {
    napi_value error;
    const char* message = operation->error.empty() ? "Virtualization guest virtio socket exchange failed" : operation->error.c_str();
    napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &error);
    napi_reject_deferred(env, operation->deferred, error);
  } else {
    napi_value result;
    napi_create_buffer_copy(env, operation->response.size(), operation->response.data(), nullptr, &result);
    napi_resolve_deferred(env, operation->deferred, result);
  }
  napi_delete_async_work(env, operation->work);
  void* retained = operation->retained_handle;
  delete operation;
  if (retained != nullptr) (void)(__bridge_transfer MOPVirtualizationGuestHandle*)retained;
}

napi_value ExchangeGuestFrame(napi_env env, napi_callback_info info) {
  size_t argc = 5;
  napi_value args[5];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 5) {
    napi_throw_type_error(env, nullptr, "exchangeGuestFrame requires a handle, port, frame, response cap, and timeout");
    return nullptr;
  }
  MOPVirtualizationGuestHandle* handle = ReadHandle(env, args[0]);
  if (handle == nullptr) return nullptr;
  uint32_t port = 0;
  uint32_t timeout_ms = 0;
  uint32_t max_response_bytes = 0;
  napi_valuetype port_type = napi_undefined;
  napi_valuetype cap_type = napi_undefined;
  napi_valuetype timeout_type = napi_undefined;
  napi_typeof(env, args[1], &port_type);
  napi_typeof(env, args[3], &cap_type);
  napi_typeof(env, args[4], &timeout_type);
  const bool is_port = port_type == napi_number;
  const bool is_cap = cap_type == napi_number;
  const bool is_timeout = timeout_type == napi_number;
  if (!is_port || !is_cap || !is_timeout ||
      napi_get_value_uint32(env, args[1], &port) != napi_ok ||
      napi_get_value_uint32(env, args[3], &max_response_bytes) != napi_ok ||
      napi_get_value_uint32(env, args[4], &timeout_ms) != napi_ok ||
      port < kMinVsockPort || port > kMaxVsockPort || max_response_bytes < 1 ||
      max_response_bytes > kMaxFrameBytes || timeout_ms < 1 || timeout_ms > 120000) {
    napi_throw_range_error(env, nullptr, "Virtualization guest virtio socket limits are invalid");
    return nullptr;
  }
  bool is_buffer = false;
  napi_is_buffer(env, args[2], &is_buffer);
  if (!is_buffer) {
    napi_throw_type_error(env, nullptr, "Virtualization guest frame must be a Buffer");
    return nullptr;
  }
  void* data = nullptr;
  size_t length = 0;
  if (napi_get_buffer_info(env, args[2], &data, &length) != napi_ok ||
      data == nullptr || length < 1 || length > kMaxFrameBytes) {
    napi_throw_range_error(env, nullptr, "Virtualization guest frame exceeds the byte limit");
    return nullptr;
  }
  AsyncChannelOperation* operation = new AsyncChannelOperation();
  operation->env = env;
  operation->handle = handle;
  operation->port = port;
  operation->timeout_ms = timeout_ms;
  operation->max_response_bytes = max_response_bytes;
  operation->request.assign(static_cast<unsigned char*>(data), static_cast<unsigned char*>(data) + length);
  operation->retained_handle = (__bridge_retained void*)handle;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok) {
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest frame promise could not be created");
    return nullptr;
  }
  napi_value resource_name;
  napi_create_string_utf8(env, "virtualization-guest-frame", NAPI_AUTO_LENGTH, &resource_name);
  if (napi_create_async_work(env, nullptr, resource_name,
                             [](napi_env worker_env, void* data) {
                               (void)worker_env;
                               ExecuteChannel(static_cast<AsyncChannelOperation*>(data));
                             }, CompleteChannel, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    (void)(__bridge_transfer MOPVirtualizationGuestHandle*)operation->retained_handle;
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest frame could not be queued");
    return nullptr;
  }
  return promise;
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
      CloseActiveVirtioConnections(handle);
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
    handle->magic.store(kHandleMagic, std::memory_order_release);
    handle->closed_atomic.store(false, std::memory_order_release);
    handle.queue = queue;
    handle.machine = [[VZVirtualMachine alloc] initWithConfiguration:configuration queue:queue];
    handle.listeners = [NSMutableDictionary dictionary];
    handle.listenerDelegates = [NSMutableDictionary dictionary];
    handle.imagePath = [NSString stringWithUTF8String:canonical_path.c_str()];
    handle.imageSha256 = [NSString stringWithUTF8String:expected_digest];
    handle.runtimeVersion = [NSString stringWithUTF8String:runtime_version];
    handle.bootId = nil;
    handle.closed = NO;
    napi_value result;
    if (napi_create_external(env, (__bridge_retained void*)handle, FinalizeHandle, nullptr, &result) != napi_ok) {
      handle->magic.store(0, std::memory_order_release);
      handle->closed_atomic.store(true, std::memory_order_release);
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
    }
  });
  if (rejected) {
    ThrowError(env, "Virtualization guest VM must be stopped before close");
    return nullptr;
  }
  CloseAllListeners(handle);
  dispatch_sync(handle.queue, ^{
    if (handle.closed) return;
    handle.closed = YES;
    handle->magic.store(0, std::memory_order_release);
    handle->closed_atomic.store(true, std::memory_order_release);
    handle.machine = nil;
    // Keep the serial queue alive until the external handle finalizer runs.
    // Async N-API work may still hold a retained handle after close; leaving
    // the queue available lets those callbacks observe `closed` and fail
    // closed instead of dispatching through a null queue.
  });
  CloseActiveVirtioConnections(handle);
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
  napi_value node_version;
  napi_create_string_utf8(env, NODE_VERSION_STRING, NAPI_AUTO_LENGTH, &node_version);
  napi_set_named_property(env, exports, "nativeNodeVersion", node_version);
  napi_value native_platform;
  napi_create_string_utf8(env, kNativePlatform, NAPI_AUTO_LENGTH, &native_platform);
  napi_set_named_property(env, exports, "nativePlatform", native_platform);
  napi_value native_arch;
  napi_create_string_utf8(env, kNativeArch, NAPI_AUTO_LENGTH, &native_arch);
  napi_set_named_property(env, exports, "nativeArch", native_arch);
  SetFunction(env, exports, "createGuestVm", CreateGuestVm);
  SetFunction(env, exports, "startGuestVm", StartGuestVm);
  SetFunction(env, exports, "stopGuestVm", StopGuestVm);
  SetFunction(env, exports, "statusGuestVm", StatusGuestVm);
  SetFunction(env, exports, "closeGuestVm", CloseGuestVm);
  SetFunction(env, exports, "exchangeGuestFrame", ExchangeGuestFrame);
  SetFunction(env, exports, "listenGuestPort", ListenGuestPort);
  SetFunction(env, exports, "removeGuestPort", RemoveGuestPort);
  SetFunction(env, exports, "acceptGuestConnection", AcceptGuestConnection);
  SetFunction(env, exports, "readGuestConnectionChunk", ReadGuestConnectionChunk);
  SetFunction(env, exports, "writeGuestConnectionChunk", WriteGuestConnectionChunk);
  SetFunction(env, exports, "closeGuestConnection", CloseGuestConnection);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
