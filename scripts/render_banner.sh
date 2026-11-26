#!/bin/sh
# Render assets/banner.html to PNG with headless Chrome (needs JetBrains Mono installed).
set -eu
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
render() { # name width height [query]
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size="$2,$3" --screenshot="assets/$1.png" "file://$PWD/assets/banner.html$4" 2>/dev/null
}
render banner 1280 640 ""
render x-card 1600 900 "?x"
