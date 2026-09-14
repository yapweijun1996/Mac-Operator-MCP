#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The native canonical JSON probe requires macOS." >&2
  exit 1
fi

repository_root="$(cd "$(dirname "$0")/.." && pwd)"
swiftc_path="$(command -v swiftc || true)"
if [ -z "$swiftc_path" ]; then
  swiftc_path="$(xcrun --find swiftc)"
fi
source_file="$repository_root/packages/contracts/native/canonical_json_probe.swift"
output_directory="$repository_root/packages/contracts/dist"
output_file="$output_directory/canonical_json_probe"
vector_file="$repository_root/schemas/canonical-json-vectors.json"

if [ ! -f "$source_file" ] || [ ! -f "$vector_file" ]; then
  echo "Canonical JSON probe inputs are unavailable." >&2
  exit 1
fi

mkdir -p "$output_directory"
# Keep the probe on the Swift standard library so Command Line Tools SDK
# interface-version skew cannot silently disable the cross-runtime check.
"$swiftc_path" -O "$source_file" -o "$output_file"
if [ ! -x "$output_file" ]; then
  echo "Canonical JSON probe did not produce an executable." >&2
  exit 1
fi

"$output_file" "$vector_file"
