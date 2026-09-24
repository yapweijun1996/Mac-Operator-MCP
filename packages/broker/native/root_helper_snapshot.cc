#include <algorithm>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include "security_ed25519.h"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <initializer_list>
#include <limits.h>
#include <libproc.h>
#include <poll.h>
#include <sandbox.h>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/event.h>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace {

constexpr size_t kHeaderBytes = 12;
constexpr size_t kMaxPayloadBytes = 64 * 1024;
constexpr unsigned char kVersion = 1;
constexpr char kMagic[] = "MOPH";
constexpr int kTimeoutMs = 5'000;
constexpr unsigned long long kEnvelopeClockSkewMs = 5'000;
constexpr unsigned long long kMaxEnvelopeLifetimeMs = 600'000;
constexpr unsigned long long kMaxAttestationLifetimeMs = 60'000;
constexpr char kRequestDomain[] = "mac-operator-root-helper-snapshot-v0.1\0";
constexpr char kResponseDomain[] = "mac-operator-root-helper-snapshot-response-v0.1\0";
constexpr char kAppSandboxRequestDomain[] = "mac-operator-app-sandbox-helper-v0.1\0";
constexpr char kAppSandboxResponseDomain[] = "mac-operator-app-sandbox-helper-response-v0.1\0";
constexpr char kRootHelperMechanism[] = "darwin-root-helper-snapshot-v1";
constexpr char kAppSandboxMechanism[] = "darwin-app-sandbox-helper-v1";
constexpr char kRootHelperAudience[] = "mac-operator-descriptor-helper-v0.1";
constexpr char kAppSandboxAudience[] = "mac-operator-app-sandbox-helper-v0.1";
constexpr int kNetworkProxyChildFd = 7;

volatile sig_atomic_t g_stop_requested = 0;
volatile sig_atomic_t g_active_process_group = 0;

void HandleStopSignal(int) {
  g_stop_requested = 1;
  if (g_active_process_group > 0) kill(-g_active_process_group, SIGKILL);
}

struct Handoff {
  std::vector<unsigned char> payload;
  std::vector<int> descriptors;
};

void CloseDescriptors(std::vector<int>* descriptors) {
  if (descriptors == nullptr) return;
  for (const int descriptor : *descriptors) {
    if (descriptor >= 0) close(descriptor);
  }
  descriptors->clear();
}

bool WaitReadable(int descriptor, const std::chrono::steady_clock::time_point& deadline) {
  while (true) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0) return false;
    struct pollfd poll_descriptor{};
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN | POLLHUP | POLLERR;
    const int result = poll(&poll_descriptor, 1, static_cast<int>(remaining));
    if (result > 0) {
      return (poll_descriptor.revents & (POLLIN | POLLHUP | POLLERR)) != 0 &&
          (poll_descriptor.revents & POLLNVAL) == 0;
    }
    if (result == 0) return false;
    if (errno == EINTR) continue;
    return false;
  }
}

bool SendHandoff(int socket_descriptor, const std::vector<unsigned char>& payload,
    const std::vector<int>& descriptors, std::string* error) {
  if (payload.size() > kMaxPayloadBytes || descriptors.empty() || descriptors.size() > 4) {
    if (error != nullptr) *error = "handoff limits are invalid";
    return false;
  }
  std::vector<unsigned char> frame(kHeaderBytes + payload.size());
  memcpy(frame.data(), kMagic, 4);
  frame[4] = kVersion;
  frame[5] = static_cast<unsigned char>(descriptors.size());
  frame[6] = 0;
  frame[7] = 0;
  const uint32_t encoded_length = htonl(static_cast<uint32_t>(payload.size()));
  memcpy(frame.data() + 8, &encoded_length, sizeof(encoded_length));
  if (!payload.empty()) memcpy(frame.data() + kHeaderBytes, payload.data(), payload.size());

  struct iovec outgoing_iovec{};
  outgoing_iovec.iov_base = frame.data();
  outgoing_iovec.iov_len = frame.size();
  char control[CMSG_SPACE(sizeof(int) * 4)] = {};
  struct msghdr message{};
  message.msg_iov = &outgoing_iovec;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptors.size());
  struct cmsghdr* header = CMSG_FIRSTHDR(&message);
  if (header == nullptr) {
    if (error != nullptr) *error = "SCM_RIGHTS header could not be created";
    return false;
  }
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int) * descriptors.size());
  memcpy(CMSG_DATA(header), descriptors.data(), sizeof(int) * descriptors.size());
  const ssize_t sent = sendmsg(socket_descriptor, &message, 0);
  if (sent != static_cast<ssize_t>(frame.size())) {
    if (error != nullptr) *error = "SCM_RIGHTS frame could not be sent";
    return false;
  }
  if (shutdown(socket_descriptor, SHUT_WR) != 0) {
    if (error != nullptr) *error = "handoff stream could not be half-closed";
    return false;
  }
  return true;
}

bool ReceiveHandoff(int socket_descriptor, size_t expected_descriptors, Handoff* output,
    std::string* error) {
  if (output == nullptr || expected_descriptors == 0 || expected_descriptors > 4) {
    if (error != nullptr) *error = "handoff receive limits are invalid";
    return false;
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs);
  std::vector<unsigned char> frame(kHeaderBytes + kMaxPayloadBytes);
  struct iovec incoming_iovec{};
  incoming_iovec.iov_base = frame.data();
  incoming_iovec.iov_len = frame.size();
  char control[CMSG_SPACE(sizeof(int) * 4)] = {};
  struct msghdr message{};
  message.msg_iov = &incoming_iovec;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  while (!WaitReadable(socket_descriptor, deadline)) {
    if (error != nullptr) *error = "handoff frame receive timed out";
    return false;
  }
  const ssize_t first = recvmsg(socket_descriptor, &message, MSG_DONTWAIT);
  if (first <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
    if (error != nullptr) *error = "handoff frame header is malformed";
    return false;
  }

  std::vector<int> descriptors;
  for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(0) ||
        (header->cmsg_len - CMSG_LEN(0)) % sizeof(int) != 0 ||
        header->cmsg_len > CMSG_SPACE(sizeof(int) * 4)) {
      if (error != nullptr) *error = "handoff ancillary message is malformed";
      CloseDescriptors(&descriptors);
      return false;
    }
    const size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    if (count == 0 || count > 4 || !descriptors.empty()) {
      if (error != nullptr) *error = "handoff descriptor count is malformed";
      CloseDescriptors(&descriptors);
      return false;
    }
    const auto* received = reinterpret_cast<const int*>(CMSG_DATA(header));
    for (size_t index = 0; index < count; ++index) {
      if (received[index] < 0 ||
          std::find(descriptors.begin(), descriptors.end(), received[index]) != descriptors.end()) {
        if (error != nullptr) *error = "handoff descriptor identity is malformed";
        CloseDescriptors(&descriptors);
        return false;
      }
      descriptors.push_back(received[index]);
    }
  }
  if (descriptors.size() != expected_descriptors || first < 1) {
    if (error != nullptr) *error = "handoff descriptor list is invalid";
    CloseDescriptors(&descriptors);
    return false;
  }

  size_t received = static_cast<size_t>(first);
  size_t expected_frame_length = 0;
  while (true) {
    if (received >= kHeaderBytes) {
      if (memcmp(frame.data(), kMagic, 4) != 0 || frame[4] != kVersion || frame[6] != 0 || frame[7] != 0) {
        if (error != nullptr) *error = "handoff frame magic or version is invalid";
        CloseDescriptors(&descriptors);
        return false;
      }
      uint32_t encoded_length = 0;
      memcpy(&encoded_length, frame.data() + 8, sizeof(encoded_length));
      const size_t payload_length = ntohl(encoded_length);
      expected_frame_length = kHeaderBytes + payload_length;
      if (frame[5] != expected_descriptors || payload_length > kMaxPayloadBytes ||
          expected_frame_length > frame.size() || received > expected_frame_length) {
        if (error != nullptr) *error = "handoff frame length is invalid";
        CloseDescriptors(&descriptors);
        return false;
      }
      if (received == expected_frame_length) break;
    }
    if (received == frame.size() || !WaitReadable(socket_descriptor, deadline)) {
      if (error != nullptr) *error = "handoff frame is incomplete";
      CloseDescriptors(&descriptors);
      return false;
    }
    const ssize_t additional = recv(socket_descriptor, frame.data() + received,
        frame.size() - received, MSG_DONTWAIT);
    if (additional <= 0) {
      if (error != nullptr) *error = "handoff stream ended before its declared length";
      CloseDescriptors(&descriptors);
      return false;
    }
    received += static_cast<size_t>(additional);
  }

  unsigned char trailing = 0;
  if (!WaitReadable(socket_descriptor, deadline)) {
    if (error != nullptr) *error = "handoff stream close timed out";
    CloseDescriptors(&descriptors);
    return false;
  }
  const ssize_t trailing_bytes = recv(socket_descriptor, &trailing, sizeof(trailing), MSG_DONTWAIT);
  if (trailing_bytes != 0) {
    if (error != nullptr) *error = "handoff stream contains trailing bytes";
    CloseDescriptors(&descriptors);
    return false;
  }
  for (const int descriptor : descriptors) {
    if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
        (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0) {
      if (error != nullptr) *error = "received descriptor close-on-exec setup failed";
      CloseDescriptors(&descriptors);
      return false;
    }
  }
  const uint32_t encoded_length = [&]() {
    uint32_t value = 0;
    memcpy(&value, frame.data() + 8, sizeof(value));
    return ntohl(value);
  }();
  output->payload.assign(frame.begin() + kHeaderBytes, frame.begin() + kHeaderBytes + encoded_length);
  output->descriptors = std::move(descriptors);
  return true;
}

bool ReadPeerProcessIdentity(int descriptor, pid_t* process_id, uint64_t* start_time_micros, std::string* error) {
  if (process_id == nullptr || start_time_micros == nullptr) return false;
  pid_t peer_pid = 0;
  socklen_t peer_pid_size = sizeof(peer_pid);
  if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &peer_pid, &peer_pid_size) != 0 ||
      peer_pid_size != sizeof(peer_pid) || peer_pid <= 0) {
    if (error != nullptr) *error = "peer process identity is unavailable";
    return false;
  }
  struct proc_bsdinfo bsd_info{};
  if (proc_pidinfo(peer_pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != sizeof(bsd_info) ||
      bsd_info.pbi_start_tvsec < 0 || bsd_info.pbi_start_tvusec < 0 || bsd_info.pbi_start_tvusec > 999'999) {
    if (error != nullptr) *error = "peer process start time is unavailable";
    return false;
  }
  *process_id = peer_pid;
  *start_time_micros = static_cast<uint64_t>(bsd_info.pbi_start_tvsec) * 1'000'000ULL +
      static_cast<uint64_t>(bsd_info.pbi_start_tvusec);
  return *start_time_micros > 0;
}

bool VerifyPeer(int descriptor, uid_t expected_uid, gid_t expected_gid, pid_t* process_id,
    uint64_t* start_time_micros, std::string* error) {
  uid_t uid = 0;
  gid_t gid = 0;
  if (getpeereid(descriptor, &uid, &gid) != 0 || uid != expected_uid || gid != expected_gid) {
    if (error != nullptr) *error = "peer credentials are not authorized";
    return false;
  }
  return ReadPeerProcessIdentity(descriptor, process_id, start_time_micros, error);
}

struct JsonValue {
  enum class Type { kNull, kBoolean, kNumber, kString, kArray, kObject };

  Type type = Type::kNull;
  bool boolean_value = false;
  std::string string_value;
  std::string number_value;
  std::vector<JsonValue> array_value;
  std::vector<std::pair<std::string, JsonValue>> object_value;
};

void AppendUtf8(uint32_t code_point, std::string* output) {
  if (code_point <= 0x7f) {
    output->push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7ff) {
    output->push_back(static_cast<char>(0xc0 | (code_point >> 6)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else if (code_point <= 0xffff) {
    output->push_back(static_cast<char>(0xe0 | (code_point >> 12)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else {
    output->push_back(static_cast<char>(0xf0 | (code_point >> 18)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output->push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  }
}

bool IsContinuation(unsigned char value) {
  return (value & 0xc0) == 0x80;
}

int HexValue(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

class JsonParser {
 public:
  explicit JsonParser(const std::string& input) : input_(input) {}

  bool Parse(JsonValue* output) {
    if (output == nullptr || !ParseValue(0, output)) return false;
    SkipWhitespace();
    return position_ == input_.size();
  }

 private:
  bool ParseValue(size_t depth, JsonValue* output) {
    if (depth > 64) return false;
    SkipWhitespace();
    if (position_ >= input_.size()) return false;
    switch (input_[position_]) {
      case '{': return ParseObject(depth, output);
      case '[': return ParseArray(depth, output);
      case '"':
        output->type = JsonValue::Type::kString;
        return ParseString(&output->string_value);
      case 't':
        if (!Consume("true")) return false;
        output->type = JsonValue::Type::kBoolean;
        output->boolean_value = true;
        return true;
      case 'f':
        if (!Consume("false")) return false;
        output->type = JsonValue::Type::kBoolean;
        output->boolean_value = false;
        return true;
      case 'n':
        if (!Consume("null")) return false;
        output->type = JsonValue::Type::kNull;
        return true;
      default:
        output->type = JsonValue::Type::kNumber;
        return ParseInteger(&output->number_value);
    }
  }

  bool ParseObject(size_t depth, JsonValue* output) {
    ++position_;
    output->type = JsonValue::Type::kObject;
    output->object_value.clear();
    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == '}') {
      ++position_;
      return true;
    }
    while (position_ < input_.size()) {
      std::string key;
      SkipWhitespace();
      if (!ParseString(&key)) return false;
      if (std::any_of(output->object_value.begin(), output->object_value.end(),
          [&key](const auto& entry) { return entry.first == key; })) return false;
      SkipWhitespace();
      if (position_ >= input_.size() || input_[position_] != ':') return false;
      ++position_;
      JsonValue value;
      if (!ParseValue(depth + 1, &value)) return false;
      output->object_value.emplace_back(std::move(key), std::move(value));
      SkipWhitespace();
      if (position_ >= input_.size()) return false;
      if (input_[position_] == '}') {
        ++position_;
        return true;
      }
      if (input_[position_] != ',') return false;
      ++position_;
    }
    return false;
  }

  bool ParseArray(size_t depth, JsonValue* output) {
    ++position_;
    output->type = JsonValue::Type::kArray;
    output->array_value.clear();
    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == ']') {
      ++position_;
      return true;
    }
    while (position_ < input_.size()) {
      JsonValue value;
      if (!ParseValue(depth + 1, &value)) return false;
      output->array_value.push_back(std::move(value));
      SkipWhitespace();
      if (position_ >= input_.size()) return false;
      if (input_[position_] == ']') {
        ++position_;
        return true;
      }
      if (input_[position_] != ',') return false;
      ++position_;
    }
    return false;
  }

  bool ParseString(std::string* output) {
    if (output == nullptr || position_ >= input_.size() || input_[position_] != '"') return false;
    ++position_;
    output->clear();
    while (position_ < input_.size()) {
      const unsigned char value = static_cast<unsigned char>(input_[position_++]);
      if (value == '"') return true;
      if (value < 0x20) return false;
      if (value != '\\') {
        if (value < 0x80) {
          output->push_back(static_cast<char>(value));
          continue;
        }
        size_t width = 0;
        if (value >= 0xc2 && value <= 0xdf) width = 2;
        else if (value >= 0xe0 && value <= 0xef) width = 3;
        else if (value >= 0xf0 && value <= 0xf4) width = 4;
        else return false;
        if (position_ + width - 1 > input_.size()) return false;
        if ((width >= 2 && !IsContinuation(static_cast<unsigned char>(input_[position_]))) ||
            (width >= 3 && !IsContinuation(static_cast<unsigned char>(input_[position_ + 1]))) ||
            (width == 4 && !IsContinuation(static_cast<unsigned char>(input_[position_ + 2])))) return false;
        if (width == 3 && value == 0xe0 && static_cast<unsigned char>(input_[position_]) < 0xa0) return false;
        if (width == 3 && value == 0xed && static_cast<unsigned char>(input_[position_]) >= 0xa0) return false;
        if (width == 4 && value == 0xf0 && static_cast<unsigned char>(input_[position_]) < 0x90) return false;
        if (width == 4 && value == 0xf4 && static_cast<unsigned char>(input_[position_]) > 0x8f) return false;
        output->append(input_, position_ - 1, width);
        position_ += width - 1;
        continue;
      }
      if (position_ >= input_.size()) return false;
      const unsigned char escaped = static_cast<unsigned char>(input_[position_++]);
      switch (escaped) {
        case '"': output->push_back('"'); break;
        case '\\': output->push_back('\\'); break;
        case '/': output->push_back('/'); break;
        case 'b': output->push_back('\b'); break;
        case 'f': output->push_back('\f'); break;
        case 'n': output->push_back('\n'); break;
        case 'r': output->push_back('\r'); break;
        case 't': output->push_back('\t'); break;
        case 'u': {
          uint32_t code_point = 0;
          if (!ParseCodeUnit(&code_point)) return false;
          if (code_point >= 0xd800 && code_point <= 0xdbff) {
            if (position_ + 5 >= input_.size() || input_[position_] != '\\' || input_[position_ + 1] != 'u') return false;
            position_ += 2;
            uint32_t low = 0;
            if (!ParseCodeUnit(&low) || low < 0xdc00 || low > 0xdfff) return false;
            code_point = 0x10000 + ((code_point - 0xd800) << 10) + (low - 0xdc00);
          } else if (code_point >= 0xdc00 && code_point <= 0xdfff) {
            return false;
          }
          AppendUtf8(code_point, output);
          break;
        }
        default: return false;
      }
    }
    return false;
  }

  bool ParseCodeUnit(uint32_t* output) {
    if (output == nullptr || position_ + 4 > input_.size()) return false;
    uint32_t value = 0;
    for (size_t index = 0; index < 4; ++index) {
      const int digit = HexValue(static_cast<unsigned char>(input_[position_++]));
      if (digit < 0) return false;
      value = (value << 4) | static_cast<uint32_t>(digit);
    }
    *output = value;
    return true;
  }

  bool ParseInteger(std::string* output) {
    const size_t start = position_;
    bool negative = false;
    if (position_ < input_.size() && input_[position_] == '-') {
      negative = true;
      ++position_;
    }
    if (position_ >= input_.size() || input_[position_] < '0' || input_[position_] > '9') return false;
    if (input_[position_] == '0') {
      ++position_;
      if (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') return false;
    } else {
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
    }
    if (position_ < input_.size() && (input_[position_] == '.' || input_[position_] == 'e' || input_[position_] == 'E')) return false;
    std::string digits = input_.substr(start + (negative ? 1 : 0), position_ - start - (negative ? 1 : 0));
    while (digits.size() > 1 && digits.front() == '0') digits.erase(digits.begin());
    constexpr char kMaxSafeInteger[] = "9007199254740991";
    if (digits.size() > sizeof(kMaxSafeInteger) - 1 ||
        (digits.size() == sizeof(kMaxSafeInteger) - 1 && digits > kMaxSafeInteger)) return false;
    *output = digits == "0" ? "0" : (negative ? "-" + digits : digits);
    return true;
  }

  bool Consume(const char* expected) {
    const size_t length = strlen(expected);
    if (input_.compare(position_, length, expected) != 0) return false;
    position_ += length;
    return true;
  }

  void SkipWhitespace() {
    while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\n' ||
        input_[position_] == '\r' || input_[position_] == '\t')) ++position_;
  }

  const std::string& input_;
  size_t position_ = 0;
};

std::string QuoteJsonString(const std::string& value) {
  std::string output;
  output.reserve(value.size() + 2);
  output.push_back('"');
  static const char* hex = "0123456789abcdef";
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (byte < 0x20) {
          output += "\\u00";
          output.push_back(hex[(byte >> 4) & 0x0f]);
          output.push_back(hex[byte & 0x0f]);
        } else {
          output.push_back(static_cast<char>(byte));
        }
    }
  }
  output.push_back('"');
  return output;
}

std::string CanonicalJson(const JsonValue& value) {
  switch (value.type) {
    case JsonValue::Type::kNull: return "null";
    case JsonValue::Type::kBoolean: return value.boolean_value ? "true" : "false";
    case JsonValue::Type::kNumber: return value.number_value;
    case JsonValue::Type::kString: return QuoteJsonString(value.string_value);
    case JsonValue::Type::kArray: {
      std::string output = "[";
      for (size_t index = 0; index < value.array_value.size(); ++index) {
        if (index > 0) output.push_back(',');
        output += CanonicalJson(value.array_value[index]);
      }
      output.push_back(']');
      return output;
    }
    case JsonValue::Type::kObject: {
      std::vector<const std::pair<std::string, JsonValue>*> entries;
      entries.reserve(value.object_value.size());
      for (const auto& entry : value.object_value) entries.push_back(&entry);
      std::sort(entries.begin(), entries.end(), [](const auto* left, const auto* right) {
        return left->first < right->first;
      });
      std::string output = "{";
      for (size_t index = 0; index < entries.size(); ++index) {
        if (index > 0) output.push_back(',');
        output += QuoteJsonString(entries[index]->first);
        output.push_back(':');
        output += CanonicalJson(entries[index]->second);
      }
      output.push_back('}');
      return output;
    }
  }
  return "null";
}

std::string Sha256HexText(const std::string& value) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {};
  CC_SHA256(reinterpret_cast<const unsigned char*>(value.data()), static_cast<CC_LONG>(value.size()), digest);
  static const char* hex = "0123456789abcdef";
  std::string output;
  output.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (const unsigned char byte : digest) {
    output.push_back(hex[(byte >> 4) & 0x0f]);
    output.push_back(hex[byte & 0x0f]);
  }
  return output;
}

std::string Sha256HexBytes(const std::vector<unsigned char>& value) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {};
  CC_SHA256(value.data(), static_cast<CC_LONG>(value.size()), digest);
  static const char* hex = "0123456789abcdef";
  std::string output;
  output.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (const unsigned char byte : digest) {
    output.push_back(hex[(byte >> 4) & 0x0f]);
    output.push_back(hex[byte & 0x0f]);
  }
  return output;
}

std::string HmacHex(const char* domain, const std::string& digest, const std::vector<unsigned char>& key) {
  CCHmacContext context;
  CCHmacInit(&context, kCCHmacAlgSHA256, key.data(), key.size());
  CCHmacUpdate(&context, domain, strlen(domain) + 1);
  CCHmacUpdate(&context, digest.data(), digest.size());
  unsigned char result[CC_SHA256_DIGEST_LENGTH] = {};
  CCHmacFinal(&context, result);
  static const char* hex = "0123456789abcdef";
  std::string output;
  output.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (const unsigned char byte : result) {
    output.push_back(hex[(byte >> 4) & 0x0f]);
    output.push_back(hex[byte & 0x0f]);
  }
  return output;
}

bool ConstantTimeEqual(const std::string& left, const std::string& right) {
  if (left.size() != right.size()) return false;
  unsigned char difference = 0;
  for (size_t index = 0; index < left.size(); ++index) {
    difference |= static_cast<unsigned char>(left[index] ^ right[index]);
  }
  return difference == 0;
}

JsonValue StringValue(const std::string& value) {
  JsonValue result;
  result.type = JsonValue::Type::kString;
  result.string_value = value;
  return result;
}

JsonValue BooleanValue(bool value) {
  JsonValue result;
  result.type = JsonValue::Type::kBoolean;
  result.boolean_value = value;
  return result;
}

JsonValue NullValue() {
  JsonValue result;
  result.type = JsonValue::Type::kNull;
  return result;
}

JsonValue NumberValue(const std::string& value) {
  JsonValue result;
  result.type = JsonValue::Type::kNumber;
  result.number_value = value;
  return result;
}

JsonValue ObjectValue(std::vector<std::pair<std::string, JsonValue>> entries) {
  JsonValue result;
  result.type = JsonValue::Type::kObject;
  result.object_value = std::move(entries);
  return result;
}

const JsonValue* FindObjectValue(const JsonValue& value, const std::string& key) {
  if (value.type != JsonValue::Type::kObject) return nullptr;
  for (const auto& entry : value.object_value) if (entry.first == key) return &entry.second;
  return nullptr;
}

bool HasExactObjectKeys(const JsonValue& value, std::initializer_list<const char*> expected) {
  if (value.type != JsonValue::Type::kObject || value.object_value.size() != expected.size()) return false;
  return std::all_of(value.object_value.begin(), value.object_value.end(), [&expected](const auto& entry) {
    return std::any_of(expected.begin(), expected.end(), [&entry](const char* key) { return entry.first == key; });
  });
}

bool IsLowerHexDigest(const std::string& value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char item) {
    return (item >= '0' && item <= '9') || (item >= 'a' && item <= 'f');
  });
}

bool IsSafeIdentifier(const std::string& value, size_t maximum_length) {
  if (value.empty() || value.size() > maximum_length ||
      !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') ||
        (value[0] >= '0' && value[0] <= '9'))) return false;
  for (size_t index = 1; index < value.size(); ++index) {
    const char item = value[index];
    if (!((item >= 'A' && item <= 'Z') || (item >= 'a' && item <= 'z') ||
          (item >= '0' && item <= '9') || item == '.' || item == '_' || item == ':' || item == '-')) {
      return false;
    }
  }
  return true;
}

bool IsEd25519SignatureBase64(const std::string& value) {
  if (value.size() != 88 || value[value.size() - 1] != '=' || value[value.size() - 2] != '=') return false;
  for (size_t index = 0; index < value.size() - 2; ++index) {
    const char item = value[index];
    if (!((item >= 'A' && item <= 'Z') || (item >= 'a' && item <= 'z') ||
          (item >= '0' && item <= '9') || item == '+' || item == '/')) return false;
  }
  return true;
}

int Base64Value(unsigned char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return value - 'a' + 26;
  if (value >= '0' && value <= '9') return value - '0' + 52;
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

bool DecodeBase64(const std::string& value, std::vector<unsigned char>* output) {
  if (output == nullptr || value.size() % 4 != 0) return false;
  output->clear();
  output->reserve((value.size() / 4) * 3);
  for (size_t index = 0; index < value.size(); index += 4) {
    const unsigned char first = static_cast<unsigned char>(value[index]);
    const unsigned char second = static_cast<unsigned char>(value[index + 1]);
    const unsigned char third = static_cast<unsigned char>(value[index + 2]);
    const unsigned char fourth = static_cast<unsigned char>(value[index + 3]);
    const int a = Base64Value(first);
    const int b = Base64Value(second);
    const bool third_padding = third == '=';
    const bool fourth_padding = fourth == '=';
    const int c = third_padding ? 0 : Base64Value(third);
    const int d = fourth_padding ? 0 : Base64Value(fourth);
    if (a < 0 || b < 0 || c < 0 || d < 0 || (third_padding && !fourth_padding) ||
        (index + 4 != value.size() && (third_padding || fourth_padding)) ||
        (third_padding && (b & 0x0f) != 0) || (fourth_padding && !third_padding && (c & 0x03) != 0)) {
      return false;
    }
    output->push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
    if (!third_padding) output->push_back(static_cast<unsigned char>((b << 4) | (c >> 2)));
    if (!fourth_padding) output->push_back(static_cast<unsigned char>((c << 6) | d));
  }
  return true;
}

bool CurrentEpochMilliseconds(unsigned long long* output) {
  if (output == nullptr) return false;
  const auto count = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  if (count < 0) return false;
  *output = static_cast<unsigned long long>(count);
  return true;
}

bool ParseUnsignedNumber(const JsonValue* value, unsigned long long* output) {
  if (value == nullptr || output == nullptr || value->type != JsonValue::Type::kNumber || value->number_value.empty() || value->number_value[0] == '-') return false;
  unsigned long long parsed = 0;
  for (const char item : value->number_value) {
    if (item < '0' || item > '9') return false;
    const unsigned long long digit = static_cast<unsigned long long>(item - '0');
    if (parsed > (ULLONG_MAX - digit) / 10) return false;
    parsed = parsed * 10 + digit;
  }
  *output = parsed;
  return true;
}

bool ReadProtectedFile(const std::string& path, std::vector<unsigned char>* output, std::string* error) {
  if (output == nullptr || path.empty() || path[0] != '/' || path.size() >= PATH_MAX) {
    if (error != nullptr) *error = "protected file path is invalid";
    return false;
  }
  char resolved[PATH_MAX] = {};
  if (realpath(path.c_str(), resolved) == nullptr || path != resolved) {
    if (error != nullptr) *error = "protected file path is not canonical";
    return false;
  }
  struct stat path_stat{};
  if (lstat(path.c_str(), &path_stat) != 0 || !S_ISREG(path_stat.st_mode) ||
      path_stat.st_uid != getuid() || (path_stat.st_mode & 077) != 0 ||
      path_stat.st_size < 1 || path_stat.st_size > 128 * 1024) {
    if (error != nullptr) *error = "protected file identity is unsafe";
    return false;
  }
  const int descriptor = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (descriptor < 0) {
    if (error != nullptr) *error = "protected file could not be opened";
    return false;
  }
  struct stat opened_stat{};
  const bool identity_ok = fstat(descriptor, &opened_stat) == 0 &&
      opened_stat.st_dev == path_stat.st_dev && opened_stat.st_ino == path_stat.st_ino &&
      opened_stat.st_uid == path_stat.st_uid && (opened_stat.st_mode & 077) == 0 &&
      opened_stat.st_size == path_stat.st_size;
  if (!identity_ok) {
    close(descriptor);
    if (error != nullptr) *error = "protected file changed while opening";
    return false;
  }
  output->assign(static_cast<size_t>(path_stat.st_size), 0);
  size_t offset = 0;
  while (offset < output->size()) {
    const ssize_t read_bytes = pread(descriptor, output->data() + offset, output->size() - offset, static_cast<off_t>(offset));
    if (read_bytes > 0) {
      offset += static_cast<size_t>(read_bytes);
      continue;
    }
    if (read_bytes < 0 && errno == EINTR) continue;
    close(descriptor);
    if (error != nullptr) *error = "protected file read failed";
    return false;
  }
  struct stat final_stat{};
  const bool unchanged = fstat(descriptor, &final_stat) == 0 &&
      final_stat.st_dev == opened_stat.st_dev && final_stat.st_ino == opened_stat.st_ino &&
      final_stat.st_size == opened_stat.st_size && final_stat.st_mtime == opened_stat.st_mtime &&
      final_stat.st_ctime == opened_stat.st_ctime;
  close(descriptor);
  if (!unchanged) {
    if (error != nullptr) *error = "protected file changed while reading";
    output->clear();
    return false;
  }
  return true;
}

bool ReadProtectedDescriptor(int descriptor, std::vector<unsigned char>* output, std::string* error) {
  if (descriptor < 0 || output == nullptr) {
    if (error != nullptr) *error = "protected descriptor is invalid";
    return false;
  }
  struct stat descriptor_stat{};
  if (fstat(descriptor, &descriptor_stat) != 0 || !S_ISREG(descriptor_stat.st_mode) ||
      descriptor_stat.st_uid != getuid() || (descriptor_stat.st_mode & 077) != 0 ||
      descriptor_stat.st_size < 1 || descriptor_stat.st_size > 128 * 1024) {
    if (error != nullptr) *error = "protected descriptor identity is unsafe";
    return false;
  }
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
      (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0) {
    if (error != nullptr) *error = "protected descriptor close-on-exec could not be established";
    return false;
  }
  output->assign(static_cast<size_t>(descriptor_stat.st_size), 0);
  size_t offset = 0;
  while (offset < output->size()) {
    const ssize_t read_bytes = pread(descriptor, output->data() + offset,
        output->size() - offset, static_cast<off_t>(offset));
    if (read_bytes > 0) {
      offset += static_cast<size_t>(read_bytes);
      continue;
    }
    if (read_bytes < 0 && errno == EINTR) continue;
    if (error != nullptr) *error = "protected descriptor read failed";
    output->clear();
    return false;
  }
  struct stat final_stat{};
  if (fstat(descriptor, &final_stat) != 0 || final_stat.st_dev != descriptor_stat.st_dev ||
      final_stat.st_ino != descriptor_stat.st_ino || final_stat.st_uid != descriptor_stat.st_uid ||
      final_stat.st_size != descriptor_stat.st_size || final_stat.st_mtime != descriptor_stat.st_mtime ||
      final_stat.st_ctime != descriptor_stat.st_ctime) {
    if (error != nullptr) *error = "protected descriptor changed while reading";
    output->clear();
    return false;
  }
  return true;
}

bool ValidateSnapshotRoot(const std::string& path, std::string* error) {
  if (path.empty() || path[0] != '/' || path.size() >= PATH_MAX) {
    if (error != nullptr) *error = "snapshot root path is invalid";
    return false;
  }
  char resolved[PATH_MAX] = {};
  struct stat path_stat{};
  if (realpath(path.c_str(), resolved) == nullptr || path != resolved ||
      lstat(path.c_str(), &path_stat) != 0 || !S_ISDIR(path_stat.st_mode) ||
      path_stat.st_uid != getuid() || (path_stat.st_mode & 077) != 0 ||
      (path_stat.st_mode & 0700) != 0700) {
    if (error != nullptr) *error = "snapshot root identity is unsafe";
    return false;
  }
  return true;
}

bool MaterializeFileSnapshot(int descriptor, const std::string& snapshot_root,
    const std::string& expected_digest, uid_t owner_uid, gid_t owner_gid,
    bool executable, std::string* snapshot_path, std::string* error) {
  if (descriptor < 0 || snapshot_path == nullptr || !IsLowerHexDigest(expected_digest) ||
      !ValidateSnapshotRoot(snapshot_root, error)) return false;
  struct stat input_stat{};
  if (fstat(descriptor, &input_stat) != 0 || !S_ISREG(input_stat.st_mode) ||
      input_stat.st_size < 1 || input_stat.st_size > 64 * 1024 * 1024 ||
      (executable && (input_stat.st_mode & 0111) == 0)) {
    if (error != nullptr) *error = "executable descriptor is invalid";
    return false;
  }
  const std::string name = "snapshot-" + std::to_string(static_cast<unsigned long long>(getpid())) +
      "-" + std::to_string(static_cast<unsigned long long>(arc4random()));
  const std::string temporary_path = snapshot_root + "/." + name + ".partial";
  const std::string final_path = snapshot_root + "/" + name;
  if (temporary_path.size() >= PATH_MAX || final_path.size() >= PATH_MAX) {
    if (error != nullptr) *error = "snapshot path is too long";
    return false;
  }
  const mode_t output_mode = executable ? 0700 : 0600;
  const int output = open(temporary_path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, output_mode);
  if (output < 0) {
    if (error != nullptr) *error = "snapshot temporary file could not be created";
    return false;
  }
  bool success = false;
  bool output_closed = false;
  CC_SHA256_CTX digest_context;
  CC_SHA256_Init(&digest_context);
  std::vector<unsigned char> buffer(1024 * 1024);
  off_t position = 0;
  while (position < input_stat.st_size) {
    const ssize_t read_bytes = pread(descriptor, buffer.data(),
        std::min<off_t>(static_cast<off_t>(buffer.size()), input_stat.st_size - position), position);
    if (read_bytes <= 0) break;
    CC_SHA256_Update(&digest_context, buffer.data(), static_cast<CC_LONG>(read_bytes));
    ssize_t written_total = 0;
    while (written_total < read_bytes) {
      const ssize_t written = write(output, buffer.data() + written_total, static_cast<size_t>(read_bytes - written_total));
      if (written > 0) {
        written_total += written;
        continue;
      }
      if (written < 0 && errno == EINTR) continue;
      written_total = -1;
      break;
    }
    if (written_total < 0) break;
    position += read_bytes;
  }
  unsigned char digest_bytes[CC_SHA256_DIGEST_LENGTH] = {};
  CC_SHA256_Final(digest_bytes, &digest_context);
  static const char* hex = "0123456789abcdef";
  std::string observed_digest;
  observed_digest.reserve(CC_SHA256_DIGEST_LENGTH * 2);
  for (const unsigned char byte : digest_bytes) {
    observed_digest.push_back(hex[(byte >> 4) & 0x0f]);
    observed_digest.push_back(hex[byte & 0x0f]);
  }
  struct stat final_input_stat{};
  const bool input_unchanged = fstat(descriptor, &final_input_stat) == 0 &&
      final_input_stat.st_dev == input_stat.st_dev && final_input_stat.st_ino == input_stat.st_ino &&
      final_input_stat.st_size == input_stat.st_size && final_input_stat.st_mtime == input_stat.st_mtime &&
      final_input_stat.st_ctime == input_stat.st_ctime;
  if (position == input_stat.st_size && observed_digest == expected_digest && input_unchanged &&
      fchmod(output, output_mode) == 0 && fchown(output, owner_uid, owner_gid) == 0 && fsync(output) == 0) {
    if (close(output) == 0) {
      output_closed = true;
    }
    if (output_closed && rename(temporary_path.c_str(), final_path.c_str()) == 0) {
      struct stat snapshot_stat{};
      char resolved_final[PATH_MAX] = {};
      const bool final_path_is_canonical = realpath(final_path.c_str(), resolved_final) != nullptr &&
          final_path == resolved_final;
      success = lstat(final_path.c_str(), &snapshot_stat) == 0 && S_ISREG(snapshot_stat.st_mode) &&
          snapshot_stat.st_uid == owner_uid && (snapshot_stat.st_mode & 077) == 0 &&
          (!executable || (snapshot_stat.st_mode & 0111) != 0) && final_path_is_canonical;
    }
  }
  if (!success) {
    if (!output_closed) close(output);
    unlink(temporary_path.c_str());
    unlink(final_path.c_str());
    if (error != nullptr) *error = observed_digest != expected_digest
        ? "snapshot content digest does not match attestation"
        : "snapshot materialization readback failed";
    return false;
  }
  *snapshot_path = final_path;
  return true;
}

bool MaterializeSnapshot(int descriptor, const std::string& snapshot_root,
    const std::string& expected_digest, uid_t owner_uid, gid_t owner_gid,
    std::string* snapshot_path, std::string* error) {
  return MaterializeFileSnapshot(descriptor, snapshot_root, expected_digest, owner_uid, owner_gid,
      true, snapshot_path, error);
}

bool MaterializeScriptSnapshot(int descriptor, const std::string& snapshot_root,
    const std::string& expected_digest, uid_t owner_uid, gid_t owner_gid,
    std::string* script_path, std::string* error) {
  return MaterializeFileSnapshot(descriptor, snapshot_root, expected_digest, owner_uid, owner_gid,
      false, script_path, error);
}

bool LoadProbeKeyConfig(const char* config_path, std::vector<unsigned char>* key, std::string* error) {
  if (config_path == nullptr || key == nullptr) return false;
  std::vector<unsigned char> config_bytes;
  if (!ReadProtectedFile(config_path, &config_bytes, error)) return false;
  JsonValue config;
  if (!JsonParser(std::string(config_bytes.begin(), config_bytes.end())).Parse(&config) || config.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "helper key config JSON is malformed";
    return false;
  }
  const JsonValue* schema = FindObjectValue(config, "schemaVersion");
  const JsonValue* revision = FindObjectValue(config, "revision");
  const JsonValue* keys = FindObjectValue(config, "keys");
  if (!HasExactObjectKeys(config, {"schemaVersion", "revision", "keys"}) ||
      schema == nullptr || schema->type != JsonValue::Type::kString || schema->string_value != "0.1" ||
      revision == nullptr || revision->type != JsonValue::Type::kNumber || keys == nullptr ||
      keys->type != JsonValue::Type::kArray || keys->array_value.size() != 1) {
    if (error != nullptr) *error = "helper key config shape is invalid";
    return false;
  }
  unsigned long long revision_value = 0;
  if (!ParseUnsignedNumber(revision, &revision_value) || revision_value == 0) {
    if (error != nullptr) *error = "helper key config revision is invalid";
    return false;
  }
  const JsonValue& entry = keys->array_value[0];
  const JsonValue* source = FindObjectValue(entry, "keySource");
  const JsonValue* path = FindObjectValue(entry, "path");
  const JsonValue* digest = FindObjectValue(entry, "keyDigest");
  const JsonValue* not_before = FindObjectValue(entry, "notBeforeMs");
  const JsonValue* expires = FindObjectValue(entry, "expiresAtMs");
  if (entry.type != JsonValue::Type::kObject || source == nullptr || source->type != JsonValue::Type::kString ||
      source->string_value != "file" || path == nullptr || path->type != JsonValue::Type::kString ||
      digest == nullptr || digest->type != JsonValue::Type::kString || !IsLowerHexDigest(digest->string_value)) {
    if (error != nullptr) *error = "helper key config entry is invalid";
    return false;
  }
  unsigned long long not_before_value = 0;
  unsigned long long expires_value = 0;
  if (!ParseUnsignedNumber(not_before, &not_before_value) || !ParseUnsignedNumber(expires, &expires_value) ||
      expires_value <= not_before_value ||
      static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()) < not_before_value ||
      static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()) >= expires_value) {
    if (error != nullptr) *error = "helper key config validity window is invalid";
    return false;
  }
  if (!ReadProtectedFile(path->string_value, key, error) || key->size() < 32 ||
      Sha256HexBytes(*key) != digest->string_value) {
    if (error != nullptr) *error = "helper key config digest precondition failed";
    key->clear();
    return false;
  }
  return true;
}

bool LoadProbeKeyConfigFromDescriptors(int config_descriptor, int key_descriptor,
    std::vector<unsigned char>* key, std::string* error) {
  if (config_descriptor < 0 || key_descriptor < 0 || key == nullptr) return false;
  std::vector<unsigned char> config_bytes;
  if (!ReadProtectedDescriptor(config_descriptor, &config_bytes, error)) return false;
  JsonValue config;
  if (!JsonParser(std::string(config_bytes.begin(), config_bytes.end())).Parse(&config) || config.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "helper descriptor key config JSON is malformed";
    return false;
  }
  const JsonValue* schema = FindObjectValue(config, "schemaVersion");
  const JsonValue* revision = FindObjectValue(config, "revision");
  const JsonValue* keys = FindObjectValue(config, "keys");
  if (!HasExactObjectKeys(config, {"schemaVersion", "revision", "keys"}) ||
      schema == nullptr || schema->type != JsonValue::Type::kString || schema->string_value != "0.1" ||
      revision == nullptr || revision->type != JsonValue::Type::kNumber || keys == nullptr ||
      keys->type != JsonValue::Type::kArray || keys->array_value.size() != 1) {
    if (error != nullptr) *error = "helper descriptor key config shape is invalid";
    return false;
  }
  unsigned long long revision_value = 0;
  if (!ParseUnsignedNumber(revision, &revision_value) || revision_value == 0) {
    if (error != nullptr) *error = "helper descriptor key config revision is invalid";
    return false;
  }
  const JsonValue& entry = keys->array_value[0];
  const JsonValue* source = FindObjectValue(entry, "keySource");
  const JsonValue* path = FindObjectValue(entry, "path");
  const JsonValue* digest = FindObjectValue(entry, "keyDigest");
  const JsonValue* not_before = FindObjectValue(entry, "notBeforeMs");
  const JsonValue* expires = FindObjectValue(entry, "expiresAtMs");
  if (entry.type != JsonValue::Type::kObject || source == nullptr || source->type != JsonValue::Type::kString ||
      source->string_value != "descriptor" || path == nullptr || path->type != JsonValue::Type::kString ||
      path->string_value != "fd:request-key" || digest == nullptr || digest->type != JsonValue::Type::kString ||
      !IsLowerHexDigest(digest->string_value)) {
    if (error != nullptr) *error = "helper descriptor key config entry is invalid";
    return false;
  }
  unsigned long long not_before_value = 0;
  unsigned long long expires_value = 0;
  if (!ParseUnsignedNumber(not_before, &not_before_value) || !ParseUnsignedNumber(expires, &expires_value) ||
      expires_value <= not_before_value ||
      static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()) < not_before_value ||
      static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count()) >= expires_value) {
    if (error != nullptr) *error = "helper descriptor key config validity window is invalid";
    return false;
  }
  if (!ReadProtectedDescriptor(key_descriptor, key, error) || key->size() < 32 ||
      Sha256HexBytes(*key) != digest->string_value) {
    if (error != nullptr) *error = "helper descriptor key digest precondition failed";
    key->clear();
    return false;
  }
  return true;
}

struct AttestationVerificationKey {
  std::string key_id;
  std::vector<unsigned char> public_key;
};

bool LoadAttestationVerificationKeyConfig(const char* config_path,
    AttestationVerificationKey* output, std::string* error) {
  if (config_path == nullptr || output == nullptr) return false;
  std::vector<unsigned char> config_bytes;
  if (!ReadProtectedFile(config_path, &config_bytes, error)) return false;
  JsonValue config;
  if (!JsonParser(std::string(config_bytes.begin(), config_bytes.end())).Parse(&config) ||
      config.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "attestation key config JSON is malformed";
    return false;
  }
  const JsonValue* schema = FindObjectValue(config, "schemaVersion");
  const JsonValue* revision = FindObjectValue(config, "revision");
  const JsonValue* keys = FindObjectValue(config, "keys");
  if (!HasExactObjectKeys(config, {"schemaVersion", "revision", "keys"}) ||
      schema == nullptr || schema->type != JsonValue::Type::kString || schema->string_value != "0.1" ||
      revision == nullptr || revision->type != JsonValue::Type::kNumber || keys == nullptr ||
      keys->type != JsonValue::Type::kArray || keys->array_value.size() != 1) {
    if (error != nullptr) *error = "attestation key config shape is invalid";
    return false;
  }
  unsigned long long revision_value = 0;
  if (!ParseUnsignedNumber(revision, &revision_value) || revision_value == 0) {
    if (error != nullptr) *error = "attestation key config revision is invalid";
    return false;
  }
  const JsonValue& entry = keys->array_value[0];
  const JsonValue* key_id = FindObjectValue(entry, "keyId");
  const JsonValue* path = FindObjectValue(entry, "path");
  const JsonValue* digest = FindObjectValue(entry, "publicKeyDigest");
  const JsonValue* not_before = FindObjectValue(entry, "notBeforeMs");
  const JsonValue* expires = FindObjectValue(entry, "expiresAtMs");
  if (!HasExactObjectKeys(entry, {"keyId", "path", "publicKeyDigest", "notBeforeMs", "expiresAtMs"}) ||
      key_id == nullptr || key_id->type != JsonValue::Type::kString ||
      !IsSafeIdentifier(key_id->string_value, 128) || path == nullptr || path->type != JsonValue::Type::kString ||
      digest == nullptr || digest->type != JsonValue::Type::kString || !IsLowerHexDigest(digest->string_value)) {
    if (error != nullptr) *error = "attestation key config entry is invalid";
    return false;
  }
  unsigned long long not_before_value = 0;
  unsigned long long expires_value = 0;
  unsigned long long now_value = 0;
  if (!ParseUnsignedNumber(not_before, &not_before_value) || !ParseUnsignedNumber(expires, &expires_value) ||
      !CurrentEpochMilliseconds(&now_value) || expires_value <= not_before_value ||
      now_value < not_before_value || now_value >= expires_value) {
    if (error != nullptr) *error = "attestation key config validity window is invalid";
    return false;
  }
  std::vector<unsigned char> public_key;
  if (!ReadProtectedFile(path->string_value, &public_key, error) || public_key.size() != 32 ||
      Sha256HexBytes(public_key) != digest->string_value) {
    if (error != nullptr) *error = "attestation key config digest precondition failed";
    public_key.clear();
    return false;
  }
  output->key_id = key_id->string_value;
  output->public_key = std::move(public_key);
  return true;
}

bool LoadAttestationVerificationKeyConfigFromDescriptors(int config_descriptor, int public_key_descriptor,
    AttestationVerificationKey* output, std::string* error) {
  if (config_descriptor < 0 || public_key_descriptor < 0 || output == nullptr) return false;
  std::vector<unsigned char> config_bytes;
  if (!ReadProtectedDescriptor(config_descriptor, &config_bytes, error)) return false;
  JsonValue config;
  if (!JsonParser(std::string(config_bytes.begin(), config_bytes.end())).Parse(&config) ||
      config.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "attestation descriptor key config JSON is malformed";
    return false;
  }
  const JsonValue* schema = FindObjectValue(config, "schemaVersion");
  const JsonValue* revision = FindObjectValue(config, "revision");
  const JsonValue* keys = FindObjectValue(config, "keys");
  if (!HasExactObjectKeys(config, {"schemaVersion", "revision", "keys"}) ||
      schema == nullptr || schema->type != JsonValue::Type::kString || schema->string_value != "0.1" ||
      revision == nullptr || revision->type != JsonValue::Type::kNumber || keys == nullptr ||
      keys->type != JsonValue::Type::kArray || keys->array_value.size() != 1) {
    if (error != nullptr) *error = "attestation descriptor key config shape is invalid";
    return false;
  }
  unsigned long long revision_value = 0;
  if (!ParseUnsignedNumber(revision, &revision_value) || revision_value == 0) {
    if (error != nullptr) *error = "attestation descriptor key config revision is invalid";
    return false;
  }
  const JsonValue& entry = keys->array_value[0];
  const JsonValue* key_id = FindObjectValue(entry, "keyId");
  const JsonValue* path = FindObjectValue(entry, "path");
  const JsonValue* digest = FindObjectValue(entry, "publicKeyDigest");
  const JsonValue* not_before = FindObjectValue(entry, "notBeforeMs");
  const JsonValue* expires = FindObjectValue(entry, "expiresAtMs");
  if (!HasExactObjectKeys(entry, {"keyId", "path", "publicKeyDigest", "notBeforeMs", "expiresAtMs"}) ||
      key_id == nullptr || key_id->type != JsonValue::Type::kString ||
      !IsSafeIdentifier(key_id->string_value, 128) || path == nullptr || path->type != JsonValue::Type::kString ||
      path->string_value != "fd:attestation-key" || digest == nullptr || digest->type != JsonValue::Type::kString ||
      !IsLowerHexDigest(digest->string_value)) {
    if (error != nullptr) *error = "attestation descriptor key config entry is invalid";
    return false;
  }
  unsigned long long not_before_value = 0;
  unsigned long long expires_value = 0;
  unsigned long long now_value = 0;
  if (!ParseUnsignedNumber(not_before, &not_before_value) || !ParseUnsignedNumber(expires, &expires_value) ||
      !CurrentEpochMilliseconds(&now_value) || expires_value <= not_before_value ||
      now_value < not_before_value || now_value >= expires_value) {
    if (error != nullptr) *error = "attestation descriptor key config validity window is invalid";
    return false;
  }
  std::vector<unsigned char> public_key;
  if (!ReadProtectedDescriptor(public_key_descriptor, &public_key, error) || public_key.size() != 32 ||
      Sha256HexBytes(public_key) != digest->string_value) {
    if (error != nullptr) *error = "attestation descriptor key digest precondition failed";
    public_key.clear();
    return false;
  }
  output->key_id = key_id->string_value;
  output->public_key = std::move(public_key);
  return true;
}

bool VerifySnapshotEnvelope(const std::string& payload, const std::vector<unsigned char>& key,
    const AttestationVerificationKey& attestation_key,
    const char* expected_mechanism, const char* expected_audience, const char* request_domain,
    std::string* request_id, std::string* unsigned_digest, std::string* executable_digest,
    std::string* error) {
  JsonValue root;
  if (!JsonParser(payload).Parse(&root) || root.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "snapshot envelope JSON is malformed";
    return false;
  }
  const JsonValue* proof = FindObjectValue(root, "authenticationProof");
  const JsonValue* schema = FindObjectValue(root, "schemaVersion");
  const JsonValue* mechanism = FindObjectValue(root, "mechanism");
  const JsonValue* request = FindObjectValue(root, "requestId");
  const JsonValue* timestamp = FindObjectValue(root, "timestampMs");
  const JsonValue* expires = FindObjectValue(root, "expiresAtMs");
  unsigned long long timestamp_value = 0;
  unsigned long long expires_value = 0;
  unsigned long long now_value = 0;
  const std::string request_tail = request != nullptr && request->type == JsonValue::Type::kString
      ? request->string_value.substr(strlen("snapshot-request:")) : std::string();
  if (proof == nullptr || proof->type != JsonValue::Type::kString || proof->string_value.size() != 64 ||
      !std::all_of(proof->string_value.begin(), proof->string_value.end(), [](char value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
      }) || schema == nullptr || schema->type != JsonValue::Type::kString || schema->string_value != "0.1" ||
      expected_mechanism == nullptr || mechanism == nullptr || mechanism->type != JsonValue::Type::kString ||
      mechanism->string_value != expected_mechanism ||
      request == nullptr || request->type != JsonValue::Type::kString ||
      request->string_value.rfind("snapshot-request:", 0) != 0 || request_tail.size() < 16 ||
      !IsSafeIdentifier(request_tail, 112) ||
      !ParseUnsignedNumber(timestamp, &timestamp_value) || !ParseUnsignedNumber(expires, &expires_value) ||
      !CurrentEpochMilliseconds(&now_value) || expires_value <= timestamp_value ||
      expires_value - timestamp_value > kMaxEnvelopeLifetimeMs ||
      timestamp_value > now_value + kEnvelopeClockSkewMs || now_value >= expires_value) {
    if (error != nullptr) *error = "snapshot envelope fields are malformed";
    return false;
  }
  JsonValue unsigned_root = root;
  unsigned_root.object_value.erase(std::remove_if(unsigned_root.object_value.begin(), unsigned_root.object_value.end(),
      [](const auto& entry) { return entry.first == "authenticationProof"; }), unsigned_root.object_value.end());
  const std::string unsigned_canonical = CanonicalJson(unsigned_root);
  const std::string digest = Sha256HexText(unsigned_canonical);
  if (request_domain == nullptr || !ConstantTimeEqual(proof->string_value, HmacHex(request_domain, digest, key))) {
    if (error != nullptr) *error = "snapshot envelope authentication failed";
    return false;
  }
  const JsonValue* signed_attestation = FindObjectValue(root, "signedAttestation");
  const JsonValue* attestation_payload = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "payload");
  const JsonValue* attestation_schema = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "schemaVersion");
  const JsonValue* attestation_key_id = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "keyId");
  const JsonValue* attestation_algorithm = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "algorithm");
  const JsonValue* attestation_issued = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "issuedAtMs");
  const JsonValue* attestation_expires = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "expiresAtMs");
  const JsonValue* attestation_digest = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "payloadDigest");
  const JsonValue* attestation_signature = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "signature");
  const JsonValue* attestation_audience = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "audience");
  const JsonValue* content_digest = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "executableContentSha256");
  unsigned long long attestation_issued_value = 0;
  unsigned long long attestation_expires_value = 0;
  if (expected_audience == nullptr || signed_attestation == nullptr || attestation_payload == nullptr ||
      attestation_audience == nullptr || attestation_audience->type != JsonValue::Type::kString ||
      attestation_audience->string_value != expected_audience || content_digest == nullptr ||
      signed_attestation->type != JsonValue::Type::kObject || attestation_payload->type != JsonValue::Type::kObject ||
      attestation_schema == nullptr || attestation_schema->type != JsonValue::Type::kString || attestation_schema->string_value != "0.1" ||
      attestation_key_id == nullptr || attestation_key_id->type != JsonValue::Type::kString ||
      !IsSafeIdentifier(attestation_key_id->string_value, 128) ||
      attestation_key_id->string_value != attestation_key.key_id ||
      attestation_algorithm == nullptr || attestation_algorithm->type != JsonValue::Type::kString || attestation_algorithm->string_value != "Ed25519" ||
      !ParseUnsignedNumber(attestation_issued, &attestation_issued_value) ||
      !ParseUnsignedNumber(attestation_expires, &attestation_expires_value) ||
      attestation_expires_value <= attestation_issued_value ||
      attestation_expires_value - attestation_issued_value > kMaxAttestationLifetimeMs ||
      attestation_issued_value > now_value + kEnvelopeClockSkewMs || now_value >= attestation_expires_value ||
      attestation_digest == nullptr || attestation_digest->type != JsonValue::Type::kString ||
      !IsLowerHexDigest(attestation_digest->string_value) ||
      attestation_signature == nullptr || attestation_signature->type != JsonValue::Type::kString ||
      !IsEd25519SignatureBase64(attestation_signature->string_value) ||
      content_digest->type != JsonValue::Type::kString || !IsLowerHexDigest(content_digest->string_value) ||
      Sha256HexText(CanonicalJson(*attestation_payload)) != attestation_digest->string_value) {
    if (error != nullptr) *error = "snapshot executable digest is missing";
    return false;
  }
  JsonValue unsigned_attestation = *signed_attestation;
  unsigned_attestation.object_value.erase(std::remove_if(unsigned_attestation.object_value.begin(),
      unsigned_attestation.object_value.end(), [](const auto& entry) { return entry.first == "signature"; }),
      unsigned_attestation.object_value.end());
  std::vector<unsigned char> signature;
  if (!DecodeBase64(attestation_signature->string_value, &signature) || signature.size() != 64 ||
      !mac_operator::security::VerifyEd25519Message(attestation_key.public_key, signature,
          CanonicalJson(unsigned_attestation), error)) {
    if (error != nullptr && error->empty()) *error = "snapshot Ed25519 attestation signature verification failed";
    return false;
  }
  if (request_id != nullptr) *request_id = request->string_value;
  if (unsigned_digest != nullptr) *unsigned_digest = digest;
  if (executable_digest != nullptr) *executable_digest = content_digest->string_value;
  return true;
}

struct SnapshotTask {
  std::string execution_kind;
  std::string script_content_sha256;
  std::vector<std::string> args;
  std::vector<std::pair<std::string, std::string>> environment;
  unsigned long long timeout_ms = 0;
  unsigned long long output_cap_bytes = 0;
  bool network_enabled = false;
  std::string network_channel_token;
};

struct AuthorityPollContext {
  std::string socket_path;
  std::vector<unsigned char> key;
  std::string request_digest;
  unsigned long long expires_at_ms = 0;
};

bool WriteAll(int descriptor, const std::string& value);
bool SetNonBlocking(int descriptor);

bool IsSafeEnvironmentKey(const std::string& key) {
  if (key.empty() || key.size() > 64 || !((key[0] >= 'A' && key[0] <= 'Z') || key[0] == '_')) return false;
  for (size_t index = 1; index < key.size(); ++index) {
    const char value = key[index];
    if (!((value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_')) return false;
  }
  return true;
}

bool IsSecretEnvironmentKey(const std::string& key) {
  return key.find("PASSWORD") != std::string::npos || key.find("TOKEN") != std::string::npos ||
      key.find("SECRET") != std::string::npos || key.find("PRIVATE") != std::string::npos ||
      key.find("CREDENTIAL") != std::string::npos || key.find("COOKIE") != std::string::npos;
}

bool ExtractSnapshotTask(const std::string& payload, SnapshotTask* task, bool app_sandbox_execution,
    bool app_sandbox_network_execution, std::string* error) {
  if (task == nullptr) return false;
  JsonValue root;
  if (!JsonParser(payload).Parse(&root) || root.type != JsonValue::Type::kObject) {
    if (error != nullptr) *error = "snapshot task JSON is malformed";
    return false;
  }
  const JsonValue* args = FindObjectValue(root, "args");
  const JsonValue* environment = FindObjectValue(root, "environment");
  const JsonValue* timeout = FindObjectValue(root, "timeoutMs");
  const JsonValue* output_cap = FindObjectValue(root, "outputCapBytes");
  const JsonValue* execution_kind = FindObjectValue(root, "executionKind");
  const JsonValue* script_content_sha256 = FindObjectValue(root, "scriptContentSha256");
  const JsonValue* network_channel_token = FindObjectValue(root, "networkChannelToken");
  const JsonValue* signed_attestation = FindObjectValue(root, "signedAttestation");
  const JsonValue* attestation_payload = signed_attestation == nullptr
      ? nullptr : FindObjectValue(*signed_attestation, "payload");
  const JsonValue* sandbox_profile = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "sandboxProfile");
  const JsonValue* network_policy = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "networkPolicy");
  const JsonValue* process_tree_policy = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "processTreePolicy");
  const JsonValue* credential_policy = attestation_payload == nullptr
      ? nullptr : FindObjectValue(*attestation_payload, "credentialPolicy");
  if (args == nullptr || args->type != JsonValue::Type::kArray || args->array_value.size() > 128 ||
      environment == nullptr || environment->type != JsonValue::Type::kObject || environment->object_value.size() > 64 ||
      !ParseUnsignedNumber(timeout, &task->timeout_ms) || task->timeout_ms < 25 || task->timeout_ms > 600'000 ||
      !ParseUnsignedNumber(output_cap, &task->output_cap_bytes) || task->output_cap_bytes < 1 || task->output_cap_bytes > 2 * 1024 * 1024 ||
      (app_sandbox_execution && (execution_kind == nullptr || execution_kind->type != JsonValue::Type::kString ||
        execution_kind->string_value != "posix-sh-script" || script_content_sha256 == nullptr ||
        script_content_sha256->type != JsonValue::Type::kString || !IsLowerHexDigest(script_content_sha256->string_value))) ||
      sandbox_profile == nullptr || sandbox_profile->type != JsonValue::Type::kString ||
      sandbox_profile->string_value != (app_sandbox_execution ? "app-sandbox-deny-default-v0.1" : "task-deny-default-v0.1") ||
      network_policy == nullptr || network_policy->type != JsonValue::Type::kString ||
      network_policy->string_value != (app_sandbox_network_execution ? "allowlist" : "none") ||
      (app_sandbox_network_execution && (network_channel_token == nullptr || network_channel_token->type != JsonValue::Type::kString ||
        !IsLowerHexDigest(network_channel_token->string_value))) ||
      (!app_sandbox_network_execution && network_channel_token != nullptr) ||
      process_tree_policy == nullptr || process_tree_policy->type != JsonValue::Type::kString || process_tree_policy->string_value != "single_process" ||
      credential_policy == nullptr || credential_policy->type != JsonValue::Type::kString || credential_policy->string_value != "none") {
    if (error != nullptr) *error = "snapshot task policy or bounds are invalid";
    return false;
  }
  task->execution_kind = app_sandbox_execution ? execution_kind->string_value : "binary";
  task->script_content_sha256 = app_sandbox_execution ? script_content_sha256->string_value : "";
  task->network_enabled = app_sandbox_network_execution;
  task->network_channel_token = app_sandbox_network_execution ? network_channel_token->string_value : "";
  task->args.clear();
  task->args.reserve(args->array_value.size());
  for (const JsonValue& value : args->array_value) {
    if (value.type != JsonValue::Type::kString || value.string_value.size() > 4'096 ||
        value.string_value.find('\0') != std::string::npos || value.string_value.find('\n') != std::string::npos) {
      if (error != nullptr) *error = "snapshot task argument is invalid";
      return false;
    }
    task->args.push_back(value.string_value);
  }
  task->environment.clear();
  task->environment.reserve(environment->object_value.size());
  for (const auto& entry : environment->object_value) {
    if (!IsSafeEnvironmentKey(entry.first) || IsSecretEnvironmentKey(entry.first) ||
        entry.second.type != JsonValue::Type::kString || entry.second.string_value.size() > 4'096 ||
        entry.second.string_value.find('\0') != std::string::npos || entry.second.string_value.find('\n') != std::string::npos) {
      if (error != nullptr) *error = "snapshot task environment is invalid";
      return false;
    }
    task->environment.emplace_back(entry.first, entry.second.string_value);
  }
  return true;
}

std::string RandomHex(size_t byte_count) {
  std::vector<unsigned char> bytes(byte_count);
  if (!bytes.empty()) arc4random_buf(bytes.data(), bytes.size());
  static const char* hex = "0123456789abcdef";
  std::string output;
  output.reserve(byte_count * 2);
  for (const unsigned char byte : bytes) {
    output.push_back(hex[(byte >> 4) & 0x0f]);
    output.push_back(hex[byte & 0x0f]);
  }
  return output;
}

bool CaptureSocketIdentity(const std::string& path, struct stat* identity, std::string* error) {
  if (identity == nullptr || path.empty() || path[0] != '/' || path.size() >= PATH_MAX) return false;
  char resolved[PATH_MAX] = {};
  struct stat path_stat{};
  if (realpath(path.c_str(), resolved) == nullptr || path != resolved || lstat(path.c_str(), &path_stat) != 0 ||
      !S_ISSOCK(path_stat.st_mode) || path_stat.st_uid != getuid() || (path_stat.st_mode & 077) != 0) {
    if (error != nullptr) *error = "authority socket identity is unsafe";
    return false;
  }
  *identity = path_stat;
  return true;
}

bool PollSocketForEvent(int descriptor, short events, int timeout_ms) {
  struct pollfd descriptor_state{};
  descriptor_state.fd = descriptor;
  descriptor_state.events = events;
  while (true) {
    const int result = poll(&descriptor_state, 1, timeout_ms);
    if (result > 0) return (descriptor_state.revents & (events | POLLHUP | POLLERR)) != 0 &&
        (descriptor_state.revents & POLLNVAL) == 0;
    if (result == 0) return false;
    if (errno == EINTR) continue;
    return false;
  }
}

bool PollAuthority(const AuthorityPollContext& context, std::string* error) {
  if (context.key.size() < 32 || !IsLowerHexDigest(context.request_digest) || context.expires_at_ms == 0) {
    if (error != nullptr) *error = "authority poll context is invalid";
    return false;
  }
  struct stat before{};
  if (!CaptureSocketIdentity(context.socket_path, &before, error)) return false;
  const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    if (error != nullptr) *error = "authority socket could not be created";
    return false;
  }
  const auto close_descriptor = [&]() { close(descriptor); };
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 || (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0 ||
      !SetNonBlocking(descriptor)) {
    close_descriptor();
    if (error != nullptr) *error = "authority socket close-on-exec setup failed";
    return false;
  }
  struct sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (context.socket_path.size() >= sizeof(address.sun_path)) {
    close_descriptor();
    if (error != nullptr) *error = "authority socket path is too long";
    return false;
  }
  strncpy(address.sun_path, context.socket_path.c_str(), sizeof(address.sun_path) - 1);
  const int connected = connect(descriptor, reinterpret_cast<const struct sockaddr*>(&address), sizeof(address));
  if (connected != 0 && errno != EINPROGRESS) {
    close_descriptor();
    if (error != nullptr) *error = "authority socket connection failed";
    return false;
  }
  if (connected != 0 && !PollSocketForEvent(descriptor, POLLOUT, 1'000)) {
    close_descriptor();
    if (error != nullptr) *error = "authority socket connection timed out";
    return false;
  }
  int socket_error = 0;
  socklen_t socket_error_size = sizeof(socket_error);
  if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0 || socket_error != 0) {
    close_descriptor();
    if (error != nullptr) *error = "authority socket connection was not established";
    return false;
  }
  pid_t peer_pid = 0;
  uint64_t peer_start_time_micros = 0;
  if (!VerifyPeer(descriptor, getuid(), getgid(), &peer_pid, &peer_start_time_micros, error)) {
    close_descriptor();
    return false;
  }
  const unsigned long long now_ms = static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
  if (now_ms >= context.expires_at_ms) {
    close_descriptor();
    if (error != nullptr) *error = "authority poll expired";
    return false;
  }
  const unsigned long long effective_expires_at_ms = std::min<unsigned long long>(context.expires_at_ms, now_ms + 5'000);
  const std::string request_id = "request:root-helper-authority-" + RandomHex(16);
  const std::string nonce = "root-helper-authority-nonce-" + RandomHex(16);
  JsonValue request = ObjectValue({
    {"contractVersion", StringValue("0.1")},
    {"expiresAtMs", NumberValue(std::to_string(effective_expires_at_ms))},
    {"kind", StringValue("snapshot_authority_check")},
    {"nonce", StringValue(nonce)},
    {"nonceExpiresAtMs", NumberValue(std::to_string(effective_expires_at_ms))},
    {"protocolVersion", StringValue("0.1")},
    {"requestDigest", StringValue(context.request_digest)},
    {"requestId", StringValue(request_id)},
    {"timestampMs", NumberValue(std::to_string(now_ms))}
  });
  const std::string request_proof = HmacHex(
      "mac-operator-root-helper-snapshot-authority-request-v0.1\0", Sha256HexText(CanonicalJson(request)), context.key);
  request.object_value.emplace_back("authenticationProof", StringValue(request_proof));
  const std::string serialized = CanonicalJson(request) + "\n";
  if (!WriteAll(descriptor, serialized) || !PollSocketForEvent(descriptor, POLLIN, 1'000)) {
    close_descriptor();
    if (error != nullptr) *error = "authority poll response timed out";
    return false;
  }
  std::string response_bytes;
  char buffer[4096] = {};
  bool complete = false;
  while (response_bytes.size() < 16 * 1024) {
    const ssize_t received = recv(descriptor, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (received > 0) {
      response_bytes.append(buffer, static_cast<size_t>(received));
      const size_t newline = response_bytes.find('\n');
      if (newline != std::string::npos) {
        if (response_bytes.size() != newline + 1) {
          for (size_t index = newline + 1; index < response_bytes.size(); ++index) {
            const unsigned char value = static_cast<unsigned char>(response_bytes[index]);
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n' && value != '\f') {
              close_descriptor();
              if (error != nullptr) *error = "authority response contained trailing data";
              return false;
            }
          }
        }
        response_bytes.resize(newline);
        complete = true;
        break;
      }
      continue;
    }
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      if (!PollSocketForEvent(descriptor, POLLIN, 1'000)) break;
      continue;
    }
    break;
  }
  if (!complete) {
    close_descriptor();
    if (error != nullptr) *error = "authority response was incomplete";
    return false;
  }
  JsonValue response;
  if (!JsonParser(response_bytes).Parse(&response) || response.type != JsonValue::Type::kObject) {
    close_descriptor();
    if (error != nullptr) *error = "authority response JSON is malformed";
    return false;
  }
  struct stat after{};
  const bool socket_stable = CaptureSocketIdentity(context.socket_path, &after, error) &&
      before.st_dev == after.st_dev && before.st_ino == after.st_ino;
  const JsonValue* proof = FindObjectValue(response, "responseProof");
  const JsonValue* response_id = FindObjectValue(response, "requestId");
  const JsonValue* response_digest = FindObjectValue(response, "requestDigest");
  const JsonValue* kind = FindObjectValue(response, "kind");
  const JsonValue* ok = FindObjectValue(response, "ok");
  const JsonValue* authorized = FindObjectValue(response, "authorized");
  JsonValue unsigned_response = request;
  unsigned_response.object_value.pop_back();
  JsonValue response_body = response;
  response_body.object_value.erase(std::remove_if(response_body.object_value.begin(), response_body.object_value.end(),
      [](const auto& entry) { return entry.first == "responseProof"; }), response_body.object_value.end());
  const std::string expected_response_proof = HmacHex(
      "mac-operator-root-helper-snapshot-authority-response-v0.1\0",
      Sha256HexText(CanonicalJson(unsigned_response)) + CanonicalJson(response_body), context.key);
  const bool response_identity = proof != nullptr && proof->type == JsonValue::Type::kString && proof->string_value.size() == 64 &&
      response_id != nullptr && response_id->type == JsonValue::Type::kString && response_id->string_value == request_id &&
      response_digest != nullptr && response_digest->type == JsonValue::Type::kString && response_digest->string_value == context.request_digest &&
      kind != nullptr && kind->type == JsonValue::Type::kString && kind->string_value == "snapshot_authority_check";
  const bool response_proof_ok = response_identity && ConstantTimeEqual(proof->string_value, expected_response_proof);
  const bool authorized_ok = response_proof_ok && ok != nullptr && ok->type == JsonValue::Type::kBoolean && ok->boolean_value &&
      authorized != nullptr && authorized->type == JsonValue::Type::kBoolean && authorized->boolean_value;
  close_descriptor();
  if (!socket_stable || !authorized_ok) {
    if (error != nullptr) *error = authorized_ok ? "authority socket identity changed" : "authority denied or response proof failed";
    return false;
  }
  return true;
}

bool ReadDirectoryPathFromDescriptor(int descriptor, std::string* path, std::string* error) {
  if (descriptor < 0 || path == nullptr) return false;
  struct stat descriptor_stat{};
  if (fstat(descriptor, &descriptor_stat) != 0 || !S_ISDIR(descriptor_stat.st_mode)) {
    if (error != nullptr) *error = "cwd descriptor is not a directory";
    return false;
  }
  char descriptor_path[PATH_MAX] = {};
  if (fcntl(descriptor, F_GETPATH, descriptor_path) != 0) {
    if (error != nullptr) *error = "cwd descriptor path is unavailable";
    return false;
  }
  char resolved_path[PATH_MAX] = {};
  if (realpath(descriptor_path, resolved_path) == nullptr || std::string(descriptor_path) != resolved_path) {
    if (error != nullptr) *error = "cwd descriptor path is not canonical";
    return false;
  }
  struct stat path_stat{};
  if (lstat(resolved_path, &path_stat) != 0 || !S_ISDIR(path_stat.st_mode) ||
      path_stat.st_dev != descriptor_stat.st_dev || path_stat.st_ino != descriptor_stat.st_ino) {
    if (error != nullptr) *error = "cwd descriptor identity changed";
    return false;
  }
  *path = resolved_path;
  return true;
}

bool QuoteSandboxPath(const std::string& path, std::string* quoted, std::string* error) {
  if (quoted == nullptr || path.empty() || path[0] != '/' || path.size() >= PATH_MAX) return false;
  std::string result = "\"";
  for (const unsigned char value : path) {
    if (value < 0x20 || value == 0x7f) {
      if (error != nullptr) *error = "sandbox path contains a control character";
      return false;
    }
    if (value == '\\' || value == '"') result.push_back('\\');
    result.push_back(static_cast<char>(value));
  }
  result.push_back('"');
  *quoted = std::move(result);
  return true;
}

bool BuildProbeSandboxProfile(const std::string& snapshot_path, const std::string& cwd_path,
    std::string* profile, std::string* error) {
  std::string snapshot_literal;
  std::string cwd_literal;
  if (!QuoteSandboxPath(snapshot_path, &snapshot_literal, error) || !QuoteSandboxPath(cwd_path, &cwd_literal, error)) return false;
  *profile = "(version 1)\n"
      "(import \"system.sb\")\n"
      "(deny default)\n"
      "(allow process-exec (literal " + snapshot_literal + "))\n"
      "(allow file-read* (literal " + snapshot_literal + "))\n"
      "(allow file-read* (subpath \"/System/Library\"))\n"
      "(allow file-read* (subpath \"/usr/lib\"))\n"
      "(allow file-read* (subpath \"/usr/share\"))\n"
      "(allow file-read* (subpath \"/private/etc/ssl\"))\n"
      "(allow file-read* (literal \"/private/etc/hosts\"))\n"
      "(allow file-read* (literal \"/private/etc/resolv.conf\"))\n"
      "(allow file-read* (literal \"/usr/bin/true\"))\n"
      "(allow file-read* (subpath " + cwd_literal + "))\n";
  if (profile->size() > 16 * 1024) {
    if (error != nullptr) *error = "sandbox profile exceeds the probe bound";
    profile->clear();
    return false;
  }
  return true;
}

const char* SignalName(int signal_number) {
  switch (signal_number) {
    case SIGABRT: return "SIGABRT";
    case SIGALRM: return "SIGALRM";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGHUP: return "SIGHUP";
    case SIGILL: return "SIGILL";
    case SIGINT: return "SIGINT";
    case SIGKILL: return "SIGKILL";
    case SIGPIPE: return "SIGPIPE";
    case SIGQUIT: return "SIGQUIT";
    case SIGSEGV: return "SIGSEGV";
    case SIGTERM: return "SIGTERM";
    case SIGTRAP: return "SIGTRAP";
    default: return "SIGUNKNOWN";
  }
}

std::string SafeProcessOutput(const std::string& value) {
  std::string output;
  output.reserve(value.size());
  for (const unsigned char byte : value) output.push_back(byte < 0x80 ? static_cast<char>(byte) : '?');
  return output;
}

bool SetNonBlocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool ReadProcessIdentity(pid_t pid, pid_t* process_group_id, uint64_t* start_time_micros) {
  if (pid <= 0 || process_group_id == nullptr || start_time_micros == nullptr) return false;
  struct proc_bsdinfo bsd_info{};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) != sizeof(bsd_info) ||
      bsd_info.pbi_start_tvsec < 0 || bsd_info.pbi_start_tvusec < 0 || bsd_info.pbi_start_tvusec > 999'999) {
    return false;
  }
  *process_group_id = bsd_info.pbi_pgid;
  *start_time_micros = static_cast<uint64_t>(bsd_info.pbi_start_tvsec) * 1'000'000ULL +
      static_cast<uint64_t>(bsd_info.pbi_start_tvusec);
  return *process_group_id > 0 && *start_time_micros > 0;
}

void KillProcessGroupMembers(pid_t process_group_id, const std::vector<pid_t>& additional_processes = {}) {
  if (process_group_id <= 0) return;
  kill(-process_group_id, SIGKILL);
  for (const pid_t process_id : additional_processes) if (process_id > 0) kill(process_id, SIGKILL);
}

bool ApplyProbeSandbox(const std::string& profile) {
  char* sandbox_error = nullptr;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  const int result = sandbox_init(profile.c_str(), 0, &sandbox_error);
  if (sandbox_error != nullptr) sandbox_free_error(sandbox_error);
#pragma clang diagnostic pop
  return result == 0;
}

bool ReadPipe(int descriptor, std::string* output, size_t* total_bytes, size_t cap, bool* closed, bool* overflow) {
  std::vector<char> buffer(16 * 1024);
  while (true) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count > 0) {
      *total_bytes += static_cast<size_t>(count);
      if (*total_bytes > cap) {
        *overflow = true;
        return true;
      }
      output->append(buffer.data(), static_cast<size_t>(count));
      continue;
    }
    if (count == 0) {
      *closed = true;
      return true;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    return false;
  }
}

bool ExecuteBoundedSnapshot(const std::string& snapshot_path, const std::string& script_path,
    int cwd_descriptor, int network_descriptor, const SnapshotTask& task,
    uid_t peer_uid, gid_t peer_gid, const AuthorityPollContext* authority, JsonValue* result,
    std::string* error, std::string* authority_error, bool app_sandbox_execution,
    int event_socket, const std::string& request_id, const std::string& unsigned_digest,
    const std::vector<unsigned char>& response_key, const char* response_domain) {
  if (authority_error != nullptr) authority_error->clear();
  if (result == nullptr || snapshot_path.empty() || (app_sandbox_execution && script_path.empty()) || cwd_descriptor < 0 || peer_uid == 0 ||
      (getuid() != 0 && (peer_uid != getuid() || peer_gid != getgid()))) {
    if (error != nullptr) *error = "snapshot execution credentials are not authorized";
    return false;
  }
  std::string cwd_path;
  if (!app_sandbox_execution && !ReadDirectoryPathFromDescriptor(cwd_descriptor, &cwd_path, error)) return false;
  if (app_sandbox_execution) {
    struct stat cwd_stat{};
    if (fstat(cwd_descriptor, &cwd_stat) != 0 || !S_ISDIR(cwd_stat.st_mode)) {
      if (error != nullptr) *error = "App Sandbox cwd descriptor is not a directory";
      return false;
    }
  }
  struct stat snapshot_stat{};
  char resolved_snapshot[PATH_MAX] = {};
  if (realpath(snapshot_path.c_str(), resolved_snapshot) == nullptr || snapshot_path != resolved_snapshot ||
      lstat(snapshot_path.c_str(), &snapshot_stat) != 0 || !S_ISREG(snapshot_stat.st_mode) ||
      snapshot_stat.st_uid != getuid() || (snapshot_stat.st_mode & 077) != 0 || (snapshot_stat.st_mode & 0111) == 0) {
    if (error != nullptr) *error = "snapshot executable readback is unsafe";
    return false;
  }
  std::string profile;
  if (!app_sandbox_execution && !BuildProbeSandboxProfile(snapshot_path, cwd_path, &profile, error)) return false;
  if (authority != nullptr && !PollAuthority(*authority, authority_error)) return true;
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
    if (stdout_pipe[0] >= 0) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
    if (stderr_pipe[0] >= 0) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
    if (error != nullptr) *error = "snapshot output pipes could not be created";
    return false;
  }
  const auto close_pipes = [&]() {
    close(stdout_pipe[0]); close(stdout_pipe[1]); close(stderr_pipe[0]); close(stderr_pipe[1]);
  };
  int exec_gate[2] = {-1, -1};
  if (app_sandbox_execution && (pipe(exec_gate) != 0 ||
      fcntl(exec_gate[0], F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(exec_gate[1], F_SETFD, FD_CLOEXEC) != 0)) {
    if (exec_gate[0] >= 0) close(exec_gate[0]);
    if (exec_gate[1] >= 0) close(exec_gate[1]);
    close_pipes();
    if (error != nullptr) *error = "App Sandbox process monitor gate could not be created";
    return false;
  }
  const auto started = std::chrono::steady_clock::now();
  const pid_t child = fork();
  if (child < 0) {
    if (exec_gate[0] >= 0) close(exec_gate[0]);
    if (exec_gate[1] >= 0) close(exec_gate[1]);
    close_pipes();
    if (error != nullptr) *error = "snapshot child could not be forked";
    return false;
  }
  if (child == 0) {
    if (setpgid(0, 0) != 0) _exit(127);
    if (exec_gate[1] >= 0) close(exec_gate[1]);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 || dup2(stderr_pipe[1], STDERR_FILENO) < 0) _exit(127);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    int child_cwd_descriptor = -1;
    if (app_sandbox_execution) {
      // The handoff descriptors normally occupy low descriptor numbers. Keep
      // the cwd descriptor alive across the control-descriptor cleanup below,
      // and stage the optional network capability before that cleanup too.
      child_cwd_descriptor = fcntl(cwd_descriptor, F_DUPFD_CLOEXEC, 8);
      if (child_cwd_descriptor < 0) _exit(127);
      if (task.network_enabled) {
        if (network_descriptor < 0 || dup2(network_descriptor, kNetworkProxyChildFd) < 0 ||
            fcntl(kNetworkProxyChildFd, F_SETFD, fcntl(kNetworkProxyChildFd, F_GETFD) & ~FD_CLOEXEC) < 0) _exit(127);
      }
      // The helper's descriptor-passed key material is never part of the task
      // environment. The network capability, when present, is re-homed onto a
      // dedicated inherited FD after the control descriptors are closed.
      for (int descriptor = 3; descriptor <= 6; ++descriptor) close(descriptor);
    }
    if (app_sandbox_execution) {
      if (fchdir(child_cwd_descriptor) != 0) _exit(127);
      close(child_cwd_descriptor);
    } else if (chdir(cwd_path.c_str()) != 0) {
      _exit(127);
    }
    if (getuid() == 0) {
      if (setgid(peer_gid) != 0 || setuid(peer_uid) != 0) _exit(127);
    }
    while (environ != nullptr && environ[0] != nullptr) {
      const char* separator = strchr(environ[0], '=');
      if (separator == nullptr) _exit(127);
      const std::string environment_key(environ[0], static_cast<size_t>(separator - environ[0]));
      if (unsetenv(environment_key.c_str()) != 0) _exit(127);
    }
    std::vector<std::string> environment_storage;
    std::vector<char*> environment_values;
    environment_storage.reserve(task.environment.size());
    environment_values.reserve(task.environment.size() + 1);
    for (const auto& entry : task.environment) {
      environment_storage.push_back(entry.first + "=" + entry.second);
    }
    for (std::string& entry : environment_storage) environment_values.push_back(entry.data());
    if (task.network_enabled) {
      environment_storage.push_back("MOP_NETWORK_PROXY_FD=" + std::to_string(kNetworkProxyChildFd));
      environment_storage.push_back("MOP_NETWORK_PROXY_TOKEN=" + task.network_channel_token);
    }
    environment_values.clear();
    environment_values.reserve(environment_storage.size() + 1);
    for (std::string& entry : environment_storage) environment_values.push_back(entry.data());
    environment_values.push_back(nullptr);
    if (!app_sandbox_execution && !ApplyProbeSandbox(profile)) _exit(126);
    // App Sandbox currently rejects executing a freshly materialized arbitrary
    // binary from the container (EPERM on macOS 26). Keep this candidate on
    // the fixed system-published /bin/sh interpreter and materialize only the
    // Broker-owned script source until a signed task executable strategy is
    // separately proven. Interpreter and script materialization are still
    // verified before this point.
    const std::string execution_path = app_sandbox_execution ? "/bin/sh" : snapshot_path;
    std::vector<std::string> argument_storage;
    argument_storage.reserve(task.args.size() + (app_sandbox_execution ? 2 : 1));
    argument_storage.push_back(execution_path);
    if (app_sandbox_execution) argument_storage.push_back(script_path);
    for (const std::string& argument : task.args) argument_storage.push_back(argument);
    std::vector<char*> arguments;
    arguments.reserve(argument_storage.size() + 1);
    for (std::string& argument : argument_storage) arguments.push_back(argument.data());
    arguments.push_back(nullptr);
    if (exec_gate[0] >= 0) {
      char release = 0;
      ssize_t received = 0;
      do received = read(exec_gate[0], &release, sizeof(release)); while (received < 0 && errno == EINTR);
      close(exec_gate[0]);
      if (received != 1 || release != 1) _exit(127);
    }
    execve(execution_path.c_str(), arguments.data(), environment_values.data());
    if (app_sandbox_execution) dprintf(STDERR_FILENO, "app-sandbox helper execve failed: %s\n", strerror(errno));
    _exit(127);
  }
  if (exec_gate[0] >= 0) {
    close(exec_gate[0]);
    exec_gate[0] = -1;
  }
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);
  SetNonBlocking(stdout_pipe[0]);
  SetNonBlocking(stderr_pipe[0]);
  bool process_tree_violation = false;
  bool transport_lost = false;
  int process_kqueue = -1;
  std::vector<pid_t> observed_forked_processes;
  setpgid(child, child);
  g_active_process_group = child;
  if (app_sandbox_execution) {
    process_kqueue = kqueue();
    struct kevent monitor_event{};
    EV_SET(&monitor_event, static_cast<uintptr_t>(child), EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_FORK | NOTE_EXIT, 0, nullptr);
    if (process_kqueue < 0 || kevent(process_kqueue, &monitor_event, 1, nullptr, 0, nullptr) != 0) {
      process_tree_violation = true;
      if (process_kqueue >= 0) {
        close(process_kqueue);
        process_kqueue = -1;
      }
      if (exec_gate[1] >= 0) {
        close(exec_gate[1]);
        exec_gate[1] = -1;
      }
      KillProcessGroupMembers(child);
    } else {
      char release = 1;
      ssize_t written = 0;
      do written = write(exec_gate[1], &release, sizeof(release)); while (written < 0 && errno == EINTR);
      close(exec_gate[1]);
      exec_gate[1] = -1;
      if (written != 1) {
        process_tree_violation = true;
        KillProcessGroupMembers(child);
      }
    }
  }
  if (app_sandbox_execution && !process_tree_violation) {
    pid_t process_group_id = 0;
    uint64_t start_time_micros = 0;
    if (event_socket < 0 || response_domain == nullptr ||
        !ReadProcessIdentity(child, &process_group_id, &start_time_micros)) {
      process_tree_violation = true;
      KillProcessGroupMembers(child);
    } else {
      JsonValue descendants;
      descendants.type = JsonValue::Type::kArray;
      JsonValue snapshot = ObjectValue({
        {"identity", ObjectValue({
          {"pid", NumberValue(std::to_string(static_cast<unsigned long long>(child)))},
          {"processGroupId", NumberValue(std::to_string(static_cast<unsigned long long>(process_group_id)))},
          {"startTimeMicros", NumberValue(std::to_string(static_cast<unsigned long long>(start_time_micros)))}
        })},
        {"descendants", std::move(descendants)}
      });
      JsonValue event_body = ObjectValue({
        {"kind", StringValue("process_started")},
        {"requestId", StringValue(request_id)},
        {"snapshot", std::move(snapshot)}
      });
      const std::string event_proof = HmacHex(response_domain, unsigned_digest + CanonicalJson(event_body), response_key);
      event_body.object_value.emplace_back("eventProof", StringValue(event_proof));
      if (!WriteAll(event_socket, CanonicalJson(event_body) + "\n")) {
        transport_lost = true;
        KillProcessGroupMembers(child);
      }
    }
  }
  std::string stdout_value;
  std::string stderr_value;
  size_t total_output = 0;
  bool stdout_closed = false;
  bool stderr_closed = false;
  bool output_overflow = false;
  bool timeout = false;
  bool authority_revoked = false;
  int wait_status = 0;
  bool termination_observed = false;
  auto next_authority_poll = std::chrono::steady_clock::now();
  const auto close_output_pipes = [&]() {
    if (!stdout_closed) {
      close(stdout_pipe[0]);
      stdout_pipe[0] = -1;
      stdout_closed = true;
    }
    if (!stderr_closed) {
      close(stderr_pipe[0]);
      stderr_pipe[0] = -1;
      stderr_closed = true;
    }
  };
  const auto terminate_owned_processes = [&]() {
    KillProcessGroupMembers(child, observed_forked_processes);
    close_output_pipes();
  };
  while (!stdout_closed || !stderr_closed || !termination_observed) {
    if (g_stop_requested && !termination_observed) {
      transport_lost = true;
      terminate_owned_processes();
    }
    struct pollfd descriptors[2] = {};
    nfds_t descriptor_count = 0;
    if (!stdout_closed) { descriptors[descriptor_count].fd = stdout_pipe[0]; descriptors[descriptor_count].events = POLLIN | POLLHUP | POLLERR; ++descriptor_count; }
    if (!stderr_closed) { descriptors[descriptor_count].fd = stderr_pipe[0]; descriptors[descriptor_count].events = POLLIN | POLLHUP | POLLERR; ++descriptor_count; }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    if (elapsed >= static_cast<long long>(task.timeout_ms) && !termination_observed) {
      timeout = true;
      terminate_owned_processes();
    }
    if (authority != nullptr && !authority_revoked && std::chrono::steady_clock::now() >= next_authority_poll) {
      std::string poll_error;
      if (!PollAuthority(*authority, &poll_error)) {
        authority_revoked = true;
        if (authority_error != nullptr) *authority_error = poll_error;
        if (!termination_observed) terminate_owned_processes();
      }
      next_authority_poll = std::chrono::steady_clock::now() + std::chrono::milliseconds(25);
    }
    if (app_sandbox_execution && process_kqueue >= 0 && !termination_observed && !process_tree_violation && !transport_lost) {
      struct kevent process_event{};
      struct timespec no_wait{};
      const int event_count = kevent(process_kqueue, nullptr, 0, &process_event, 1, &no_wait);
      if (event_count < 0 && errno != EINTR) {
        process_tree_violation = true;
        terminate_owned_processes();
      } else if (event_count > 0 && ((process_event.flags & EV_ERROR) != 0 ||
          process_event.filter != EVFILT_PROC || (process_event.fflags & NOTE_FORK) != 0)) {
        process_tree_violation = true;
        if ((process_event.fflags & NOTE_FORK) != 0) {
          const pid_t forked_process = static_cast<pid_t>(process_event.fflags & NOTE_PDATAMASK);
          if (forked_process > 0) observed_forked_processes.push_back(forked_process);
        }
        terminate_owned_processes();
      }
    }
    const int remaining = timeout ? 50 : static_cast<int>(std::min<unsigned long long>(task.timeout_ms - static_cast<unsigned long long>(std::min<long long>(elapsed, task.timeout_ms)), 50));
    if (descriptor_count > 0) poll(descriptors, descriptor_count, remaining);
    if (!stdout_closed && !ReadPipe(stdout_pipe[0], &stdout_value, &total_output, task.output_cap_bytes, &stdout_closed, &output_overflow)) break;
    if (!stderr_closed && !ReadPipe(stderr_pipe[0], &stderr_value, &total_output, task.output_cap_bytes, &stderr_closed, &output_overflow)) break;
    if (output_overflow && !termination_observed) {
      terminate_owned_processes();
      timeout = false;
    }
    const pid_t waited = waitpid(child, &wait_status, WNOHANG);
    if (waited == child) termination_observed = true;
    else if (waited < 0 && errno != EINTR) break;
    if (output_overflow && termination_observed && stdout_closed && stderr_closed) break;
  }
  if (!termination_observed) {
    terminate_owned_processes();
    while (waitpid(child, &wait_status, 0) < 0 && errno == EINTR) {}
    termination_observed = true;
  }
  if (!stdout_closed) ReadPipe(stdout_pipe[0], &stdout_value, &total_output, task.output_cap_bytes, &stdout_closed, &output_overflow);
  if (!stderr_closed) ReadPipe(stderr_pipe[0], &stderr_value, &total_output, task.output_cap_bytes, &stderr_closed, &output_overflow);
  if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
  if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
  if (process_kqueue >= 0) close(process_kqueue);
  if (exec_gate[1] >= 0) close(exec_gate[1]);
  g_active_process_group = 0;
  if (authority != nullptr && !authority_revoked) {
    std::string poll_error;
    if (!PollAuthority(*authority, &poll_error)) {
      authority_revoked = true;
      if (authority_error != nullptr) *authority_error = poll_error;
    }
  }
  const auto duration_ms = static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - started).count());
  std::string state;
  std::string result_class;
  JsonValue exit_code = NullValue();
  JsonValue signal = NullValue();
  if (authority_revoked || process_tree_violation || transport_lost) {
    state = "unknown";
    result_class = "UNKNOWN_OUTCOME";
  } else if (timeout) {
    state = "timed_out";
    result_class = "TIMEOUT";
    signal = StringValue("SIGKILL");
  } else if (output_overflow) {
    state = "failed";
    result_class = "OUTPUT_LIMIT";
    signal = StringValue("SIGKILL");
  } else if (WIFEXITED(wait_status)) {
    state = "completed";
    const int code = WEXITSTATUS(wait_status);
    exit_code = NumberValue(std::to_string(code));
    result_class = code == 0 ? "SUCCEEDED" : "EXECUTION_FAILED";
  } else if (WIFSIGNALED(wait_status)) {
    state = "failed";
    result_class = "EXECUTION_FAILED";
    signal = StringValue(SignalName(WTERMSIG(wait_status)));
  } else {
    state = "unknown";
    result_class = "UNKNOWN_OUTCOME";
  }
  *result = ObjectValue({
    {"durationMs", NumberValue(std::to_string(duration_ms))},
    {"exitCode", std::move(exit_code)},
    {"processGroupId", NumberValue(std::to_string(static_cast<unsigned long long>(child)))},
    {"processId", NumberValue(std::to_string(static_cast<unsigned long long>(child)))},
    {"resultClass", StringValue(result_class)},
    {"signal", std::move(signal)},
    {"state", StringValue(state)},
    {"stderr", StringValue(SafeProcessOutput(stderr_value))},
    {"stdout", StringValue(SafeProcessOutput(stdout_value))},
    {"terminationObserved", BooleanValue(termination_observed)},
    {"truncated", BooleanValue(output_overflow)}
  });
  return true;
}

bool WriteAll(int descriptor, const std::string& value) {
  size_t offset = 0;
  while (offset < value.size()) {
    const ssize_t written = write(descriptor, value.data() + offset, value.size() - offset);
    if (written > 0) {
      offset += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

int ProbeServer(const char* socket_path, const std::vector<unsigned char>& key,
    const AttestationVerificationKey& attestation_key, const char* snapshot_root, bool execute,
    const char* authority_socket, const std::vector<unsigned char>* authority_key,
    const char* expected_mechanism, const char* expected_audience,
    const char* request_domain, const char* response_domain, const char* probe_name,
    bool app_sandbox_execution, bool app_sandbox_network_execution) {
  struct sockaddr_un address{};
  if (socket_path == nullptr || strlen(socket_path) == 0 || strlen(socket_path) >= sizeof(address.sun_path) || key.size() < 32) {
    std::fprintf(stderr, "root-helper native auth probe failed: socket path\n");
    return 1;
  }
  const int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0) return 1;
  const auto close_listener = [&]() { close(listener); unlink(socket_path); };
  if (fcntl(listener, F_SETFD, FD_CLOEXEC) != 0) {
    close_listener();
    return 1;
  }
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
  if (bind(listener, reinterpret_cast<const struct sockaddr*>(&address), sizeof(address)) != 0 ||
      chmod(socket_path, 0600) != 0 || listen(listener, 1) != 0) {
    close_listener();
    return 1;
  }
  const int client = accept(listener, nullptr, nullptr);
  close(listener);
  if (client < 0) {
    unlink(socket_path);
    return 1;
  }
  if (fcntl(client, F_SETFD, FD_CLOEXEC) != 0 || (fcntl(client, F_GETFD) & FD_CLOEXEC) == 0) {
    close(client);
    unlink(socket_path);
    return 1;
  }
  std::string error;
  pid_t peer_pid = 0;
  uint64_t peer_start_time_micros = 0;
  const bool peer_ok = VerifyPeer(client, getuid(), getgid(), &peer_pid, &peer_start_time_micros, &error);
  Handoff handoff;
  const size_t expected_descriptors = app_sandbox_execution ? (app_sandbox_network_execution ? 4 : 3) : 2;
  const bool frame_ok = peer_ok && ReceiveHandoff(client, expected_descriptors, &handoff, &error);
  std::string request_id;
  std::string unsigned_digest;
  std::string executable_digest;
  const bool auth_ok = frame_ok && VerifySnapshotEnvelope(
      std::string(handoff.payload.begin(), handoff.payload.end()), key, attestation_key,
      expected_mechanism, expected_audience, request_domain,
      &request_id, &unsigned_digest, &executable_digest, &error);
  if (auth_ok) {
    AuthorityPollContext authority_context;
    const AuthorityPollContext* authority = nullptr;
    if (execute && authority_socket != nullptr && authority_key != nullptr) {
      JsonValue signed_envelope;
      const std::string serialized_payload(handoff.payload.begin(), handoff.payload.end());
      const JsonValue* expires_at = nullptr;
      if (!JsonParser(serialized_payload).Parse(&signed_envelope) || signed_envelope.type != JsonValue::Type::kObject ||
          (expires_at = FindObjectValue(signed_envelope, "expiresAtMs")) == nullptr ||
          !ParseUnsignedNumber(expires_at, &authority_context.expires_at_ms)) {
        error = "snapshot authority expiry is invalid";
      } else {
        authority_context.socket_path = authority_socket;
        authority_context.key = *authority_key;
        authority_context.request_digest = Sha256HexText(CanonicalJson(signed_envelope));
        authority = &authority_context;
      }
    }
    if (execute && authority_socket != nullptr && authority == nullptr) {
      CloseDescriptors(&handoff.descriptors);
      close(client);
      unlink(socket_path);
      std::fprintf(stderr, "root-helper native authority probe request rejected: %s\n", error.c_str());
      return 1;
    }
    SnapshotTask task;
    if (execute && !ExtractSnapshotTask(std::string(handoff.payload.begin(), handoff.payload.end()), &task,
        app_sandbox_execution, app_sandbox_network_execution, &error)) {
      CloseDescriptors(&handoff.descriptors);
      close(client);
      unlink(socket_path);
      std::fprintf(stderr, "root-helper native execution probe task rejected: %s\n", error.c_str());
      return 1;
    }
    std::string snapshot_path;
    if (snapshot_root == nullptr || !MaterializeSnapshot(handoff.descriptors[0], snapshot_root, executable_digest,
        getuid(), getgid(), &snapshot_path, &error)) {
      CloseDescriptors(&handoff.descriptors);
      close(client);
      unlink(socket_path);
      std::fprintf(stderr, "root-helper native auth probe snapshot failed: %s\n", error.c_str());
      return 1;
    }
    std::string script_path;
    if (app_sandbox_execution && !MaterializeScriptSnapshot(handoff.descriptors[2], snapshot_root,
        task.script_content_sha256, getuid(), getgid(), &script_path, &error)) {
      unlink(snapshot_path.c_str());
      CloseDescriptors(&handoff.descriptors);
      close(client);
      unlink(socket_path);
      std::fprintf(stderr, "app-sandbox helper script materialization failed: %s\n", error.c_str());
      return 1;
    }
    JsonValue body;
    std::string summary_execution = "disabled";
    if (execute) {
      JsonValue result;
      std::string authority_error;
      if (!ExecuteBoundedSnapshot(snapshot_path, script_path, handoff.descriptors[1],
          app_sandbox_network_execution ? handoff.descriptors[3] : -1, task, getuid(), getgid(), authority, &result, &error, &authority_error,
          app_sandbox_execution, app_sandbox_execution ? client : -1, request_id, unsigned_digest, key, response_domain)) {
        unlink(snapshot_path.c_str());
        if (!script_path.empty()) unlink(script_path.c_str());
        CloseDescriptors(&handoff.descriptors);
        close(client);
        unlink(socket_path);
        std::fprintf(stderr, "root-helper native execution probe failed: %s\n", error.c_str());
        return 1;
      }
      if (!authority_error.empty()) {
        body = ObjectValue({
          {"error", ObjectValue({{"message", StringValue("Root-helper snapshot authority changed during execution")}, {"retryable", BooleanValue(true)}})},
          {"ok", BooleanValue(false)},
          {"requestId", StringValue(request_id)},
          {"resultClass", StringValue("UNKNOWN_OUTCOME")}
        });
        summary_execution = "authority_denied_or_lost";
      } else {
        body = ObjectValue({
          {"ok", BooleanValue(true)},
          {"requestId", StringValue(request_id)},
          {"result", std::move(result)}
        });
        summary_execution = authority == nullptr ? "verified" : "verified_with_authority_poll";
      }
    } else {
      body = ObjectValue({
        {"error", ObjectValue({{"message", StringValue("Native probe only; production execution is disabled")}, {"retryable", BooleanValue(false)}})},
        {"ok", BooleanValue(false)},
        {"requestId", StringValue(request_id)},
        {"resultClass", StringValue("POLICY_DENIED")}
      });
    }
    const bool snapshot_cleaned = unlink(snapshot_path.c_str()) == 0;
    const bool script_cleaned = script_path.empty() || unlink(script_path.c_str()) == 0;
    if (!snapshot_cleaned || !script_cleaned) {
      CloseDescriptors(&handoff.descriptors);
      close(client);
      unlink(socket_path);
      std::fprintf(stderr, "root-helper native auth probe snapshot cleanup failed\n");
      return 1;
    }
    const std::string response_proof = HmacHex(response_domain, unsigned_digest + CanonicalJson(body), key);
    body.object_value.emplace_back("responseProof", StringValue(response_proof));
    const bool response_ok = WriteAll(client, CanonicalJson(body) + "\n");
    shutdown(client, SHUT_WR);
    CloseDescriptors(&handoff.descriptors);
    close(client);
    unlink(socket_path);
    if (!response_ok) {
      std::fprintf(stderr, "root-helper native auth probe failed: response\n");
      return 1;
    }
    std::printf("{\"probe\":\"%s\",\"peerCredentials\":\"verified\",\"peerProcessIdentity\":\"verified\",\"requestHmac\":\"verified\",\"responseHmac\":\"verified\",\"snapshotMaterialization\":\"verified\",\"execution\":\"%s\"}\n", probe_name == nullptr ? "native-auth-roundtrip" : probe_name, summary_execution.c_str());
    return 0;
  }
  CloseDescriptors(&handoff.descriptors);
  close(client);
  unlink(socket_path);
  std::fprintf(stderr, "root-helper native auth probe rejected request: %s\n", error.c_str());
  return 1;
}

int ProbeServerFromConfig(const char* socket_path, const char* config_path, const char* attestation_config_path,
    const char* snapshot_root, bool execute, const char* authority_socket, const char* authority_config_path,
    const char* expected_mechanism = kRootHelperMechanism, const char* expected_audience = kRootHelperAudience,
    const char* request_domain = kRequestDomain, const char* response_domain = kResponseDomain,
    const char* probe_name = "root-helper-native-auth-roundtrip", bool app_sandbox_execution = false,
    bool app_sandbox_network_execution = false,
    int request_config_descriptor = -1, int attestation_config_descriptor = -1,
    int request_key_descriptor = -1, int attestation_key_descriptor = -1) {
  std::vector<unsigned char> key;
  AttestationVerificationKey attestation_key;
  std::vector<unsigned char> authority_key;
  std::string error;
  const bool descriptor_config = request_config_descriptor >= 0 || attestation_config_descriptor >= 0 ||
      request_key_descriptor >= 0 || attestation_key_descriptor >= 0;
  if (descriptor_config && (request_config_descriptor < 0 || attestation_config_descriptor < 0 ||
      request_key_descriptor < 0 || attestation_key_descriptor < 0)) {
    std::fprintf(stderr, "root-helper native auth rejected incomplete descriptor configuration\n");
    return 1;
  }
  if (!(descriptor_config
      ? LoadProbeKeyConfigFromDescriptors(request_config_descriptor, request_key_descriptor, &key, &error)
      : LoadProbeKeyConfig(config_path, &key, &error))) {
    std::fprintf(stderr, "root-helper native auth probe rejected key config: %s\n", error.c_str());
    return 1;
  }
  if (!(descriptor_config
      ? LoadAttestationVerificationKeyConfigFromDescriptors(attestation_config_descriptor, attestation_key_descriptor, &attestation_key, &error)
      : LoadAttestationVerificationKeyConfig(attestation_config_path, &attestation_key, &error))) {
    std::fprintf(stderr, "root-helper native auth probe rejected attestation key config: %s\n", error.c_str());
    std::fill(key.begin(), key.end(), 0);
    return 1;
  }
  if (authority_socket != nullptr && !LoadProbeKeyConfig(authority_config_path, &authority_key, &error)) {
    std::fprintf(stderr, "root-helper native authority probe rejected key config: %s\n", error.c_str());
    std::fill(key.begin(), key.end(), 0);
    std::fill(attestation_key.public_key.begin(), attestation_key.public_key.end(), 0);
    return 1;
  }
  const int result = ProbeServer(socket_path, key, attestation_key, snapshot_root, execute,
      authority_socket, authority_socket == nullptr ? nullptr : &authority_key,
      expected_mechanism, expected_audience, request_domain, response_domain,
      probe_name, app_sandbox_execution, app_sandbox_network_execution);
  std::fill(key.begin(), key.end(), 0);
  std::fill(attestation_key.public_key.begin(), attestation_key.public_key.end(), 0);
  std::fill(authority_key.begin(), authority_key.end(), 0);
  return result;
}

int SelfTest() {
  int sockets[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
    std::fprintf(stderr, "root-helper native probe failed: socketpair\n");
    return 1;
  }
  int executable = open("/usr/bin/true", O_RDONLY | O_CLOEXEC);
  if (executable < 0) {
    close(sockets[0]);
    close(sockets[1]);
    std::fprintf(stderr, "root-helper native probe failed: executable descriptor\n");
    return 1;
  }
  const std::string text = "native-root-helper-snapshot-roundtrip-v0.1";
  const std::vector<unsigned char> payload(text.begin(), text.end());
  std::string error;
  const bool sent = SendHandoff(sockets[0], payload, {executable}, &error);
  close(executable);
  Handoff received;
  pid_t peer_pid = 0;
  uint64_t peer_start_time_micros = 0;
  const bool peer_ok = sent && VerifyPeer(sockets[1], getuid(), getgid(), &peer_pid, &peer_start_time_micros, &error);
  const bool received_ok = peer_ok && ReceiveHandoff(sockets[1], 1, &received, &error);
  close(sockets[0]);
  close(sockets[1]);
  const bool payload_ok = received_ok && std::string(received.payload.begin(), received.payload.end()) == text;
  const bool fd_ok = received_ok && received.descriptors.size() == 1 &&
      (fcntl(received.descriptors[0], F_GETFD) & FD_CLOEXEC) != 0;
  CloseDescriptors(&received.descriptors);
  if (!payload_ok || !fd_ok) {
    std::fprintf(stderr, "root-helper native probe failed: %s\n", error.c_str());
    return 1;
  }
  std::printf("{\"probe\":\"root-helper-native-roundtrip\",\"available\":false,\"peerCredentials\":\"verified\",\"peerProcessIdentity\":\"verified\",\"frame\":\"verified\",\"fdTransfer\":\"verified\",\"productionServe\":\"disabled\"}\n");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  signal(SIGTERM, HandleStopSignal);
  signal(SIGINT, HandleStopSignal);
  if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) return SelfTest();
  if (argc == 6 && (std::strcmp(argv[1], "--probe-server-config") == 0 ||
      std::strcmp(argv[1], "--probe-execute-config") == 0)) {
    return ProbeServerFromConfig(argv[2], argv[3], argv[4], argv[5],
        std::strcmp(argv[1], "--probe-execute-config") == 0, nullptr, nullptr);
  }
  if (argc == 8 && std::strcmp(argv[1], "--probe-execute-authority-config") == 0) {
    return ProbeServerFromConfig(argv[2], argv[3], argv[4], argv[5], true, argv[6], argv[7]);
  }
  if (argc == 6 && std::strcmp(argv[1], "--probe-app-sandbox-config") == 0) {
    return ProbeServerFromConfig(argv[2], argv[3], argv[4], argv[5], true, nullptr, nullptr,
        kAppSandboxMechanism, kAppSandboxAudience, kAppSandboxRequestDomain,
        kAppSandboxResponseDomain, "app-sandbox-helper-roundtrip", true);
  }
  if (argc == 6 && std::strcmp(argv[1], "--app-sandbox-execute-config") == 0) {
    return ProbeServerFromConfig(argv[2], argv[3], argv[4], argv[5], true, nullptr, nullptr,
        kAppSandboxMechanism, kAppSandboxAudience, kAppSandboxRequestDomain,
        kAppSandboxResponseDomain, "app-sandbox-helper-execution", true);
  }
  if (argc == 8 && (std::strcmp(argv[1], "--app-sandbox-execute-fds") == 0 ||
      std::strcmp(argv[1], "--app-sandbox-execute-network-fds") == 0)) {
    const bool app_sandbox_network_execution = std::strcmp(argv[1], "--app-sandbox-execute-network-fds") == 0;
    char* end = nullptr;
    const long request_config_descriptor = std::strtol(argv[3], &end, 10);
    if (end == nullptr || *end != '\0') return 2;
    end = nullptr;
    const long attestation_config_descriptor = std::strtol(argv[4], &end, 10);
    if (end == nullptr || *end != '\0') return 2;
    end = nullptr;
    const long request_key_descriptor = std::strtol(argv[5], &end, 10);
    if (end == nullptr || *end != '\0') return 2;
    end = nullptr;
    const long attestation_key_descriptor = std::strtol(argv[6], &end, 10);
    if (end == nullptr || *end != '\0') return 2;
    if (request_config_descriptor < 0 || request_config_descriptor > INT_MAX ||
        attestation_config_descriptor < 0 || attestation_config_descriptor > INT_MAX ||
        request_key_descriptor < 0 || request_key_descriptor > INT_MAX ||
        attestation_key_descriptor < 0 || attestation_key_descriptor > INT_MAX) return 2;
    return ProbeServerFromConfig(argv[2], nullptr, nullptr, argv[7], true, nullptr, nullptr,
        kAppSandboxMechanism, kAppSandboxAudience, kAppSandboxRequestDomain,
        kAppSandboxResponseDomain, app_sandbox_network_execution ? "app-sandbox-helper-network-execution-fds" : "app-sandbox-helper-execution-fds",
        true, app_sandbox_network_execution,
        static_cast<int>(request_config_descriptor), static_cast<int>(attestation_config_descriptor),
        static_cast<int>(request_key_descriptor), static_cast<int>(attestation_key_descriptor));
  }
  std::fprintf(stderr, "POLICY_DENIED: native root-helper production serve is not enabled; use --self-test only\n");
  return 2;
}
