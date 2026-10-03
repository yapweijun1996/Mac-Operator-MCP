#!/bin/sh
set -eu
exec node "$(dirname "$0")/install-gui-app.mjs" "$@"
