#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The native root-helper snapshot candidate requires macOS." >&2
  exit 1
fi

source_file="$(cd "$(dirname "$0")/.." && pwd)/native/root_helper_snapshot.cc"
crypto_source_file="$(cd "$(dirname "$0")/.." && pwd)/native/security_ed25519.cc"
output_directory="$(cd "$(dirname "$0")/.." && pwd)/dist"
output_file="$output_directory/root_helper_snapshot"

mkdir -p "$output_directory"
temporary_output="$(mktemp "$output_directory/.root_helper_snapshot.XXXXXX")"
cleanup() {
  if [ -n "${temporary_output:-}" ]; then
    rm -f "$temporary_output"
  fi
}
trap cleanup 0 1 2 15

xcrun clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  "$source_file" \
  "$crypto_source_file" \
  -framework Security \
  -framework CoreFoundation \
  -o "$temporary_output"

# Ad-hoc signing makes the local artifact verifiable without claiming
# Developer ID provenance or notarization.
/usr/bin/codesign --force --sign - "$temporary_output" >/dev/null
/usr/bin/codesign --verify --strict "$temporary_output"

# Publish only an already-built and already-verified artifact. This keeps
# concurrent callers from observing a partially compiled or unsigned file.
mv -f "$temporary_output" "$output_file"
temporary_output=""
