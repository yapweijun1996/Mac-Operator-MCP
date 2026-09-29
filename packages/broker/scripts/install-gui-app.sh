#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
source_app="dist/Mac Operator GUI.app"
destination="$HOME/Applications/Mac Operator GUI.app"
if [ ! -d "$source_app" ]; then
  echo "Build Mac Operator GUI.app before installation" >&2
  exit 1
fi
if [ -e "$destination" ]; then
  echo "Mac Operator GUI.app is already installed; preserve its macOS permission identity" >&2
  exit 1
fi
mkdir -p "$HOME/Applications"
temporary="$(mktemp -d "$HOME/Applications/.mac-operator-gui.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
ditto "$source_app" "$temporary/Mac Operator GUI.app"
codesign --verify --strict "$temporary/Mac Operator GUI.app"
mv "$temporary/Mac Operator GUI.app" "$destination"
echo "$destination"
