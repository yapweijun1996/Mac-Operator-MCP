#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "aarch64" ]; then
  echo "The guest AF_VSOCK adapter must be built in the Linux ARM64 guest toolchain." >&2
  exit 1
fi

node_binary="$(command -v node)"
node_prefix="$(cd "$(dirname "$node_binary")/.." && pwd)"
node_headers="$node_prefix/include/node"
source_directory="$(cd "$(dirname "$0")/.." && pwd)"
source_file="$source_directory/native/virtualization_guest_vsock_linux.cc"
output_directory="$source_directory/dist"
output_file="$output_directory/virtualization_guest_vsock_linux.node"

if [ ! -f "$node_headers/node_api.h" ]; then
  echo "Node N-API headers were not found beside the guest Node installation." >&2
  exit 1
fi

mkdir -p "$output_directory"
temporary_output="$(mktemp "$output_directory/.virtualization_guest_vsock_linux.XXXXXX")"
cleanup() {
  if [ -n "${temporary_output:-}" ]; then rm -f "$temporary_output"; fi
}
trap cleanup 0 1 2 15

"${CXX:-c++}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -fPIC \
  -shared \
  -I"$node_headers" \
  "$source_file" \
  -o "$temporary_output"

chmod 0644 "$temporary_output"
mv -f "$temporary_output" "$output_file"
temporary_output=""
