#include "security_ed25519.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>

#include <cstddef>

namespace {

using SecurityKeyTypeSymbol = const CFStringRef*;
using SecurityAlgorithmSymbol = const SecKeyAlgorithm*;

template <typename Symbol>
Symbol FindSecuritySymbol(const char* name) {
  return reinterpret_cast<Symbol>(dlsym(RTLD_DEFAULT, name));
}

std::string ErrorDescription(CFErrorRef error) {
  if (error == nullptr) return "Security.framework returned an unspecified error";
  CFStringRef description = CFErrorCopyDescription(error);
  if (description == nullptr) return "Security.framework returned an unspecified error";
  char buffer[1'024] = {};
  const bool converted = CFStringGetCString(description, buffer, sizeof(buffer), kCFStringEncodingUTF8);
  const std::string result = converted ? buffer : "Security.framework returned an unspecified error";
  CFRelease(description);
  return result;
}

}  // namespace

namespace mac_operator::security {

bool VerifyEd25519Message(const std::vector<unsigned char>& public_key,
    const std::vector<unsigned char>& signature, const std::string& message,
    std::string* error) {
  if (public_key.size() != 32 || signature.size() != 64) {
    if (error != nullptr) *error = "native Ed25519 key or signature length is invalid";
    return false;
  }
  const SecurityKeyTypeSymbol key_type_symbol = FindSecuritySymbol<SecurityKeyTypeSymbol>(
      "kSecAttrKeyTypeEd25519");
  const SecurityAlgorithmSymbol algorithm_symbol = FindSecuritySymbol<SecurityAlgorithmSymbol>(
      "kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512");
  if (key_type_symbol == nullptr || *key_type_symbol == nullptr || algorithm_symbol == nullptr ||
      *algorithm_symbol == nullptr) {
    if (error != nullptr) *error = "native Ed25519 Security.framework symbols are unavailable";
    return false;
  }

  CFDataRef key_data = CFDataCreate(kCFAllocatorDefault, public_key.data(), public_key.size());
  if (key_data == nullptr) {
    if (error != nullptr) *error = "native Ed25519 public-key allocation failed";
    return false;
  }
  const void* attribute_keys[] = { kSecAttrKeyType, kSecAttrKeyClass };
  const void* attribute_values[] = { *key_type_symbol, kSecAttrKeyClassPublic };
  CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, attribute_keys, attribute_values, 2,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  if (attributes == nullptr) {
    CFRelease(key_data);
    if (error != nullptr) *error = "native Ed25519 key-attribute allocation failed";
    return false;
  }
  CFErrorRef key_error = nullptr;
  SecKeyRef key = SecKeyCreateWithData(key_data, attributes, &key_error);
  CFRelease(attributes);
  CFRelease(key_data);
  if (key == nullptr) {
    if (error != nullptr) *error = ErrorDescription(key_error);
    if (key_error != nullptr) CFRelease(key_error);
    return false;
  }
  if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeVerify, *algorithm_symbol)) {
    CFRelease(key);
    if (error != nullptr) *error = "native Ed25519 Security.framework algorithm is unsupported";
    return false;
  }
  CFDataRef message_data = CFDataCreate(kCFAllocatorDefault,
      reinterpret_cast<const UInt8*>(message.data()), static_cast<CFIndex>(message.size()));
  CFDataRef signature_data = CFDataCreate(kCFAllocatorDefault, signature.data(), signature.size());
  if (message_data == nullptr || signature_data == nullptr) {
    if (message_data != nullptr) CFRelease(message_data);
    if (signature_data != nullptr) CFRelease(signature_data);
    CFRelease(key);
    if (error != nullptr) *error = "native Ed25519 verification data allocation failed";
    return false;
  }
  CFErrorRef verify_error = nullptr;
  const Boolean valid = SecKeyVerifySignature(key, *algorithm_symbol, message_data, signature_data, &verify_error);
  if (valid == false && error != nullptr) *error = ErrorDescription(verify_error);
  if (verify_error != nullptr) CFRelease(verify_error);
  CFRelease(signature_data);
  CFRelease(message_data);
  CFRelease(key);
  return valid != false;
}

}  // namespace mac_operator::security
