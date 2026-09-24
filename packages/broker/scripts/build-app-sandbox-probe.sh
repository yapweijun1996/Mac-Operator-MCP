#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The App Sandbox probe requires macOS." >&2
  exit 1
fi

sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
source_root="$(cd "$(dirname "$0")/.." && pwd)"
source_file="$source_root/native/app_sandbox_probe.c"
info_plist="$source_root/native/app_sandbox_probe-Info.plist"
entitlements="$source_root/native/app_sandbox_probe.entitlements"
output_directory="$source_root/dist"
output_bundle="$output_directory/AppSandboxProbe.app"
temporary_directory="$(mktemp -d "$output_directory/.app_sandbox_probe.XXXXXX")"
temporary_bundle="$temporary_directory/AppSandboxProbe.app"

cleanup() {
  rm -rf "$temporary_directory"
}
trap cleanup 0 1 2 15

mkdir -p "$temporary_bundle/Contents/MacOS"
xcrun clang \
  -std=c17 \
  -Wall \
  -Wextra \
  -Werror \
  -isysroot "$sdk_path" \
  "$source_file" \
  -o "$temporary_bundle/Contents/MacOS/app_sandbox_probe"
cp "$info_plist" "$temporary_bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - --entitlements "$entitlements" "$temporary_bundle"
/usr/bin/codesign --verify --strict --deep "$temporary_bundle"
/usr/bin/codesign -d --entitlements :- "$temporary_bundle" >/dev/null 2>&1

rm -rf "$output_bundle"
mv "$temporary_bundle" "$output_bundle"
