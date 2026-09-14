#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The Virtualization.framework probe requires macOS." >&2
  exit 1
fi

sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
framework_path="$sdk_path/System/Library/Frameworks/Virtualization.framework"
source_file="$(cd "$(dirname "$0")/.." && pwd)/native/virtualization_sdk_probe.m"
output_directory="$(cd "$(dirname "$0")/.." && pwd)/dist"
output_file="$output_directory/mac_operator_virtualization_sdk_probe"

if [ ! -d "$framework_path" ] || [ ! -f "$framework_path/Headers/VZVirtualMachineConfiguration.h" ]; then
  echo "Virtualization.framework is not present in the active macOS SDK." >&2
  exit 1
fi

mkdir -p "$output_directory"
xcrun clang \
  -isysroot "$sdk_path" \
  -fobjc-arc \
  -framework Virtualization \
  -framework Foundation \
  "$source_file" \
  -o "$output_file"

# The probe is a local candidate artifact, not a release binary. Refuse an
# unexpected output type or writable-by-group/other file before execution.
if [ ! -f "$output_file" ] || [ "$(stat -f '%Lp' "$output_file")" != "755" ]; then
  chmod 755 "$output_file"
fi
if [ "$(stat -f '%Lp' "$output_file")" != "755" ]; then
  echo "Virtualization probe permissions are unsafe." >&2
  exit 1
fi

"$output_file"
