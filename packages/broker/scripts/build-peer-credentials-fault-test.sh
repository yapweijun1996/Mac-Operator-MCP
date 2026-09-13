#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The native fault-injection fixture requires macOS." >&2
  exit 1
fi

node_binary="$(command -v node)"
node_prefix="$(cd "$(dirname "$node_binary")/.." && pwd)"
node_headers="$node_prefix/include/node"
output_directory="$(cd "$(dirname "$0")/.." && pwd)/dist"
source_file="$(cd "$(dirname "$0")/.." && pwd)/native/peer_credentials.cc"

if [ ! -f "$node_headers/node_api.h" ]; then
  echo "Node N-API headers were not found beside the active Node installation." >&2
  exit 1
fi

mkdir -p "$output_directory"
xcrun clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -DMAC_OPERATOR_NATIVE_FAULT_INJECTION \
  -bundle \
  -undefined dynamic_lookup \
  -I"$node_headers" \
  "$source_file" \
  -o "$output_directory/peer_credentials_fault.node"
