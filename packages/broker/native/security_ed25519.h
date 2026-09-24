#pragma once

#include <string>
#include <vector>

namespace mac_operator::security {

/**
 * Verifies a raw Ed25519 public key and a 64-byte signature over the exact
 * message bytes. The implementation uses the macOS Security framework and
 * fails closed when the required native algorithm is unavailable.
 */
bool VerifyEd25519Message(const std::vector<unsigned char>& public_key,
    const std::vector<unsigned char>& signature, const std::string& message,
    std::string* error);

}  // namespace mac_operator::security
