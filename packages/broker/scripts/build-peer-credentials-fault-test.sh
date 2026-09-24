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
temporary_output="$(mktemp "$output_directory/.peer_credentials_fault.XXXXXX")"
cleanup() {
  if [ -n "${temporary_output:-}" ]; then rm -f "$temporary_output"; fi
}
trap cleanup 0 1 2 15

xcrun clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -DMAC_OPERATOR_NATIVE_FAULT_INJECTION \
  -bundle \
  -undefined dynamic_lookup \
  -framework Security \
  -framework CoreFoundation \
  -I"$node_headers" \
  "$source_file" \
  -o "$temporary_output"

mv -f "$temporary_output" "$output_directory/peer_credentials_fault.node"
temporary_output=""
