#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <node_api.h>

#include <linux/vm_sockets.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <climits>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kMaxPort = 65535;
constexpr uint32_t kMaxTimeoutMs = 120000;
constexpr uint32_t kMaxChunkBytes = 4 * 1024 * 1024 + 64 * 1024;

struct Listener {
  int descriptor = -1;
  int wake_descriptor = -1;
  std::atomic<bool> closed{false};
  std::atomic<bool> accepting{false};

  ~Listener() {
    if (descriptor >= 0) close(descriptor);
    if (wake_descriptor >= 0) close(wake_descriptor);
  }
};

struct Connection {
  explicit Connection(int socket_descriptor) : descriptor(socket_descriptor) {}
  int descriptor = -1;
  std::atomic<bool> closed{false};

  ~Connection() {
    if (descriptor >= 0) close(descriptor);
  }
};

struct AsyncBase {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  std::string error;
};

struct AcceptOperation : AsyncBase {
  std::shared_ptr<Listener> listener;
  uint32_t timeout_ms = 0;
  std::shared_ptr<Connection> connection;
};

struct ReadOperation : AsyncBase {
  std::shared_ptr<Connection> connection;
  uint32_t max_bytes = 0;
  uint32_t timeout_ms = 0;
  bool eof = false;
  std::vector<unsigned char> bytes;
};

struct WriteOperation : AsyncBase {
  std::shared_ptr<Connection> connection;
  uint32_t timeout_ms = 0;
  std::vector<unsigned char> bytes;
};

uint64_t MonotonicMilliseconds() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

int RemainingMilliseconds(uint64_t deadline_ms) {
  const uint64_t now = MonotonicMilliseconds();
  if (now >= deadline_ms) return 0;
  const uint64_t remaining = deadline_ms - now;
  return remaining > static_cast<uint64_t>(INT32_MAX) ? INT32_MAX : static_cast<int>(remaining);
}

bool IsValidTimeout(uint32_t timeout_ms) {
  return timeout_ms >= 1 && timeout_ms <= kMaxTimeoutMs;
}

std::shared_ptr<Listener>* ReadListener(napi_env env, napi_value value) {
  void* data = nullptr;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == nullptr) {
    napi_throw_type_error(env, nullptr, "Virtualization guest vsock listener is invalid");
    return nullptr;
  }
  return static_cast<std::shared_ptr<Listener>*>(data);
}

std::shared_ptr<Connection>* ReadConnection(napi_env env, napi_value value) {
  void* data = nullptr;
  if (napi_get_value_external(env, value, &data) != napi_ok || data == nullptr) {
    napi_throw_type_error(env, nullptr, "Virtualization guest vsock connection is invalid");
    return nullptr;
  }
  return static_cast<std::shared_ptr<Connection>*>(data);
}

void FinalizeListener(napi_env, void* data, void*) {
  delete static_cast<std::shared_ptr<Listener>*>(data);
}

void FinalizeConnection(napi_env, void* data, void*) {
  delete static_cast<std::shared_ptr<Connection>*>(data);
}

napi_value CreateError(napi_env env, const char* message) {
  napi_value text;
  napi_value error;
  if (napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &text) != napi_ok ||
      napi_create_error(env, nullptr, text, &error) != napi_ok) return nullptr;
  return error;
}

void Reject(napi_env env, napi_deferred deferred, const char* message) {
  napi_value error = CreateError(env, message);
  if (error != nullptr) napi_reject_deferred(env, deferred, error);
}

bool QueueWork(napi_env env, AsyncBase* operation, const char* name,
               napi_async_execute_callback execute, napi_async_complete_callback complete) {
  napi_value resource_name;
  if (napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, execute, complete, operation, &operation->work) != napi_ok ||
      napi_queue_async_work(env, operation->work) != napi_ok) {
    if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
    return false;
  }
  return true;
}

void ExecuteAccept(napi_env, void* data) {
  auto* operation = static_cast<AcceptOperation*>(data);
  const auto listener = operation->listener;
  const uint64_t deadline = MonotonicMilliseconds() + operation->timeout_ms;
  while (!listener->closed.load(std::memory_order_acquire)) {
    pollfd descriptors[2]{};
    descriptors[0].fd = listener->descriptor;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = listener->wake_descriptor;
    descriptors[1].events = POLLIN;
    const int remaining = RemainingMilliseconds(deadline);
    if (remaining == 0) return;
    const int result = poll(descriptors, 2, remaining);
    if (result == 0) return;
    if (result < 0 && errno == EINTR) continue;
    if (result < 0 || (descriptors[0].revents & (POLLERR | POLLNVAL)) != 0) {
      operation->error = "Virtualization guest vsock accept failed";
      return;
    }
    if (listener->closed.load(std::memory_order_acquire) || descriptors[1].revents != 0) return;
    if ((descriptors[0].revents & POLLIN) == 0) continue;

    sockaddr_vm peer{};
    socklen_t peer_length = sizeof(peer);
    const int accepted = accept4(listener->descriptor, reinterpret_cast<sockaddr*>(&peer), &peer_length,
                                 SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (accepted < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (accepted < 0) {
      operation->error = "Virtualization guest vsock accept failed";
      return;
    }
    if (peer_length < sizeof(sockaddr_vm) || peer.svm_family != AF_VSOCK || peer.svm_cid != VMADDR_CID_HOST) {
      close(accepted);
      continue;
    }
    operation->connection = std::make_shared<Connection>(accepted);
    return;
  }
}

void CompleteAccept(napi_env env, napi_status status, void* data) {
  auto* operation = static_cast<AcceptOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    Reject(env, operation->deferred, operation->error.empty()
      ? "Virtualization guest vsock accept failed" : operation->error.c_str());
  } else if (operation->connection == nullptr) {
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_resolve_deferred(env, operation->deferred, null_value);
  } else {
    auto* connection = new std::shared_ptr<Connection>(std::move(operation->connection));
    napi_value external;
    if (napi_create_external(env, connection, FinalizeConnection, nullptr, &external) != napi_ok) {
      delete connection;
      Reject(env, operation->deferred, "Virtualization guest vsock connection handle could not be created");
    } else {
      napi_resolve_deferred(env, operation->deferred, external);
    }
  }
  operation->listener->accepting.store(false, std::memory_order_release);
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value CreateGuestVsockListener(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  uint32_t port = 0;
  uint32_t backlog = 0;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2 ||
      napi_get_value_uint32(env, args[0], &port) != napi_ok ||
      napi_get_value_uint32(env, args[1], &backlog) != napi_ok ||
      port < 1 || port > kMaxPort || backlog < 1 || backlog > 8) {
    napi_throw_range_error(env, nullptr, "Virtualization guest vsock listener limits are invalid");
    return nullptr;
  }

  const int descriptor = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (descriptor < 0) {
    napi_throw_error(env, nullptr, "Linux AF_VSOCK is unavailable");
    return nullptr;
  }
  const int wake_descriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (wake_descriptor < 0) {
    close(descriptor);
    napi_throw_error(env, nullptr, "Virtualization guest vsock listener wake handle is unavailable");
    return nullptr;
  }
  sockaddr_vm address{};
  address.svm_family = AF_VSOCK;
  address.svm_cid = VMADDR_CID_ANY;
  address.svm_port = port;
  if (bind(descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
      listen(descriptor, static_cast<int>(backlog)) != 0) {
    close(descriptor);
    close(wake_descriptor);
    napi_throw_error(env, nullptr, "Virtualization guest vsock listener could not bind the startup port");
    return nullptr;
  }
  auto listener = std::make_shared<Listener>();
  listener->descriptor = descriptor;
  listener->wake_descriptor = wake_descriptor;
  auto* holder = new std::shared_ptr<Listener>(std::move(listener));
  napi_value external;
  if (napi_create_external(env, holder, FinalizeListener, nullptr, &external) != napi_ok) {
    delete holder;
    napi_throw_error(env, nullptr, "Virtualization guest vsock listener handle could not be created");
    return nullptr;
  }
  return external;
}

napi_value AcceptGuestVsockConnection(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  uint32_t timeout_ms = 0;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 2 ||
      napi_get_value_uint32(env, args[1], &timeout_ms) != napi_ok || !IsValidTimeout(timeout_ms)) {
    napi_throw_range_error(env, nullptr, "Virtualization guest vsock accept timeout is invalid");
    return nullptr;
  }
  auto* holder = ReadListener(env, args[0]);
  if (holder == nullptr || !*holder) return nullptr;
  bool expected = false;
  if (!(*holder)->accepting.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    napi_throw_error(env, nullptr, "Virtualization guest vsock accept is already pending");
    return nullptr;
  }
  auto* operation = new AcceptOperation();
  operation->env = env;
  operation->listener = *holder;
  operation->timeout_ms = timeout_ms;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok ||
      !QueueWork(env, operation, "guest-vsock-accept", ExecuteAccept, CompleteAccept)) {
    operation->listener->accepting.store(false, std::memory_order_release);
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest vsock accept could not be queued");
    return nullptr;
  }
  return promise;
}

void ExecuteRead(napi_env, void* data) {
  auto* operation = static_cast<ReadOperation*>(data);
  const auto connection = operation->connection;
  if (connection->closed.load(std::memory_order_acquire)) {
    operation->eof = true;
    return;
  }
  const uint64_t deadline = MonotonicMilliseconds() + operation->timeout_ms;
  operation->bytes.resize(operation->max_bytes);
  while (true) {
    pollfd descriptor{};
    descriptor.fd = connection->descriptor;
    descriptor.events = POLLIN;
    const int remaining = RemainingMilliseconds(deadline);
    if (remaining == 0) {
      operation->error = "Virtualization guest vsock read timed out";
      operation->bytes.clear();
      return;
    }
    const int result = poll(&descriptor, 1, remaining);
    if (result == 0) {
      operation->error = "Virtualization guest vsock read timed out";
      operation->bytes.clear();
      return;
    }
    if (result < 0 && errno == EINTR) continue;
    if (result < 0 || (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
      operation->error = "Virtualization guest vsock read failed";
      operation->bytes.clear();
      return;
    }
    const ssize_t received = recv(connection->descriptor, operation->bytes.data(), operation->bytes.size(), MSG_DONTWAIT);
    if (received > 0) {
      operation->bytes.resize(static_cast<size_t>(received));
      return;
    }
    if (received == 0 || (received < 0 && (errno == ECONNRESET || errno == ENOTCONN))) {
      operation->eof = true;
      operation->bytes.clear();
      return;
    }
    if (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    operation->error = "Virtualization guest vsock read failed";
    operation->bytes.clear();
    return;
  }
}

void CompleteRead(napi_env env, napi_status status, void* data) {
  auto* operation = static_cast<ReadOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    Reject(env, operation->deferred, operation->error.empty()
      ? "Virtualization guest vsock read failed" : operation->error.c_str());
  } else if (operation->eof) {
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_resolve_deferred(env, operation->deferred, null_value);
  } else {
    napi_value buffer;
    napi_create_buffer_copy(env, operation->bytes.size(), operation->bytes.data(), nullptr, &buffer);
    napi_resolve_deferred(env, operation->deferred, buffer);
  }
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value ReadGuestVsockChunk(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  uint32_t max_bytes = 0;
  uint32_t timeout_ms = 0;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3 ||
      napi_get_value_uint32(env, args[1], &max_bytes) != napi_ok ||
      napi_get_value_uint32(env, args[2], &timeout_ms) != napi_ok ||
      max_bytes < 1 || max_bytes > kMaxChunkBytes || !IsValidTimeout(timeout_ms)) {
    napi_throw_range_error(env, nullptr, "Virtualization guest vsock read limits are invalid");
    return nullptr;
  }
  auto* holder = ReadConnection(env, args[0]);
  if (holder == nullptr || !*holder) return nullptr;
  auto* operation = new ReadOperation();
  operation->env = env;
  operation->connection = *holder;
  operation->max_bytes = max_bytes;
  operation->timeout_ms = timeout_ms;
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok ||
      !QueueWork(env, operation, "guest-vsock-read", ExecuteRead, CompleteRead)) {
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest vsock read could not be queued");
    return nullptr;
  }
  return promise;
}

bool WriteAll(int descriptor, const unsigned char* bytes, size_t length, uint64_t deadline) {
  size_t offset = 0;
  while (offset < length) {
    pollfd writable{};
    writable.fd = descriptor;
    writable.events = POLLOUT;
    const int remaining = RemainingMilliseconds(deadline);
    if (remaining == 0) return false;
    const int result = poll(&writable, 1, remaining);
    if (result == 0) return false;
    if (result < 0 && errno == EINTR) continue;
    if (result < 0 || (writable.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return false;
    const ssize_t sent = send(descriptor, bytes + offset, length - offset, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent > 0) offset += static_cast<size_t>(sent);
    else if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    else return false;
  }
  return true;
}

void ExecuteWrite(napi_env, void* data) {
  auto* operation = static_cast<WriteOperation*>(data);
  const auto connection = operation->connection;
  if (connection->closed.load(std::memory_order_acquire)) {
    operation->error = "Virtualization guest vsock connection is closed";
    return;
  }
  const uint64_t deadline = MonotonicMilliseconds() + operation->timeout_ms;
  if (!WriteAll(connection->descriptor, operation->bytes.data(), operation->bytes.size(), deadline)) {
    operation->error = RemainingMilliseconds(deadline) == 0
      ? "Virtualization guest vsock write timed out"
      : "Virtualization guest vsock write failed";
  }
}

void CompleteWrite(napi_env env, napi_status status, void* data) {
  auto* operation = static_cast<WriteOperation*>(data);
  if (status != napi_ok || !operation->error.empty()) {
    Reject(env, operation->deferred, operation->error.empty()
      ? "Virtualization guest vsock write failed" : operation->error.c_str());
  } else {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_resolve_deferred(env, operation->deferred, undefined);
  }
  if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
  delete operation;
}

napi_value WriteGuestVsockChunk(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  uint32_t timeout_ms = 0;
  bool is_buffer = false;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3 ||
      napi_is_buffer(env, args[1], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_value_uint32(env, args[2], &timeout_ms) != napi_ok || !IsValidTimeout(timeout_ms)) {
    napi_throw_range_error(env, nullptr, "Virtualization guest vsock write limits are invalid");
    return nullptr;
  }
  auto* holder = ReadConnection(env, args[0]);
  if (holder == nullptr || !*holder) return nullptr;
  void* bytes = nullptr;
  size_t length = 0;
  if (napi_get_buffer_info(env, args[1], &bytes, &length) != napi_ok ||
      bytes == nullptr || length < 1 || length > kMaxChunkBytes) {
    napi_throw_range_error(env, nullptr, "Virtualization guest vsock write frame exceeds the byte limit");
    return nullptr;
  }
  auto* operation = new WriteOperation();
  operation->env = env;
  operation->connection = *holder;
  operation->timeout_ms = timeout_ms;
  operation->bytes.assign(static_cast<unsigned char*>(bytes), static_cast<unsigned char*>(bytes) + length);
  napi_value promise;
  if (napi_create_promise(env, &operation->deferred, &promise) != napi_ok ||
      !QueueWork(env, operation, "guest-vsock-write", ExecuteWrite, CompleteWrite)) {
    delete operation;
    napi_throw_error(env, nullptr, "Virtualization guest vsock write could not be queued");
    return nullptr;
  }
  return promise;
}

napi_value CloseGuestVsockConnection(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "closeGuestVsockConnection requires a connection");
    return nullptr;
  }
  auto* holder = ReadConnection(env, args[0]);
  if (holder == nullptr || !*holder) return nullptr;
  if (!(*holder)->closed.exchange(true, std::memory_order_acq_rel)) shutdown((*holder)->descriptor, SHUT_RDWR);
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value CloseGuestVsockListener(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, nullptr, "closeGuestVsockListener requires a listener");
    return nullptr;
  }
  auto* holder = ReadListener(env, args[0]);
  if (holder == nullptr || !*holder) return nullptr;
  const auto listener = *holder;
  if (!listener->closed.exchange(true, std::memory_order_acq_rel)) {
    const uint64_t signal = 1;
    (void)write(listener->wake_descriptor, &signal, sizeof(signal));
  }
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

}  // namespace

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
    {"createGuestVsockListener", nullptr, CreateGuestVsockListener, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"acceptGuestVsockConnection", nullptr, AcceptGuestVsockConnection, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readGuestVsockChunk", nullptr, ReadGuestVsockChunk, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"writeGuestVsockChunk", nullptr, WriteGuestVsockChunk, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"closeGuestVsockConnection", nullptr, CloseGuestVsockConnection, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"closeGuestVsockListener", nullptr, CloseGuestVsockListener, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) {
    napi_throw_error(env, nullptr, "Virtualization guest vsock exports could not be initialized");
    return nullptr;
  }
  return exports;
}
