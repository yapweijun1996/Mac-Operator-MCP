#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The Virtualization.framework guest adapter requires macOS." >&2
  exit 1
fi

node_binary="$(command -v node)"
node_prefix="$(cd "$(dirname "$node_binary")/.." && pwd)"
node_headers="$node_prefix/include/node"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
source_file="$(cd "$(dirname "$0")/.." && pwd)/native/virtualization_guest.cc"
output_directory="$(cd "$(dirname "$0")/.." && pwd)/dist"
output_file="$output_directory/virtualization_guest.node"

if [ ! -f "$node_headers/node_api.h" ]; then
  echo "Node N-API headers were not found beside the active Node installation." >&2
  exit 1
fi
if [ ! -f "$sdk_path/System/Library/Frameworks/Virtualization.framework/Headers/VZVirtualMachineConfiguration.h" ]; then
  echo "Virtualization.framework is not present in the active macOS SDK." >&2
  exit 1
fi

mkdir -p "$output_directory"
xcrun clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -fobjc-arc \
  -bundle \
  -undefined dynamic_lookup \
  -framework Foundation \
  -framework Virtualization \
  -framework Security \
  -isysroot "$sdk_path" \
  -I"$node_headers" \
  -x objective-c++ \
  "$source_file" \
  -o "$output_file"

# Refuse to leave an un-verifiable native artifact in the build output. This
# checks the current artifact only; it does not establish Developer ID
# provenance or notarization.
/usr/bin/codesign --verify --strict "$output_file"
