#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist
clang -fobjc-arc -Wall -Wextra -Werror -fblocks -framework AppKit -framework Security \
  native/gui_launcher.m -o dist/gui_launcher
clang -fobjc-arc -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -fblocks -framework AppKit -framework ApplicationServices -framework ScreenCaptureKit \
  native/gui_vision.m -o dist/gui_vision
app="dist/Mac Operator GUI.app"
mkdir -p "$app/Contents/MacOS"
cp dist/gui_vision "$app/Contents/MacOS/gui_vision"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.macoperator.personal.gui</string>
  <key>CFBundleName</key><string>Mac Operator GUI</string>
  <key>CFBundleDisplayName</key><string>Mac Operator GUI</string>
  <key>CFBundleExecutable</key><string>gui_vision</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>LSUIElement</key><true/>
  <key>NSScreenCaptureUsageDescription</key><string>Capture the authorized browser window for Mac Operator visual tasks.</string>
</dict></plist>
PLIST
codesign --force --sign - "$app"
codesign --verify --strict "$app"
