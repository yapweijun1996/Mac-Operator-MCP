#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "The App Sandbox helper candidate requires macOS." >&2
  exit 1
fi

source_root="$(cd "$(dirname "$0")/.." && pwd)"
source_file="$source_root/native/root_helper_snapshot.cc"
crypto_source_file="$source_root/native/security_ed25519.cc"
info_plist="$source_root/native/app_sandbox_helper-Info.plist"
entitlements="$source_root/native/app_sandbox_helper.entitlements"
output_directory="$source_root/dist"
output_bundle="$output_directory/AppSandboxHelper.app"
temporary_directory="$(mktemp -d "$output_directory/.app_sandbox_helper.XXXXXX")"
temporary_bundle="$temporary_directory/AppSandboxHelper.app"

cleanup() {
  rm -rf "$temporary_directory"
}
trap cleanup 0 1 2 15

mkdir -p "$temporary_bundle/Contents/MacOS"
xcrun clang++ \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  "$source_file" \
  "$crypto_source_file" \
  -framework Security \
  -framework CoreFoundation \
  -o "$temporary_bundle/Contents/MacOS/app_sandbox_helper"
cp "$info_plist" "$temporary_bundle/Contents/Info.plist"
/usr/bin/codesign --force --sign - --entitlements "$entitlements" "$temporary_bundle"
/usr/bin/codesign --verify --strict --deep "$temporary_bundle"
/usr/bin/codesign -d --entitlements :- "$temporary_bundle" >/dev/null 2>&1

rm -rf "$output_bundle"
mv "$temporary_bundle" "$output_bundle"
