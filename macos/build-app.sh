#!/bin/zsh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(cd "$ROOT/.." && pwd)
APP="$ROOT/dist/UniFi-Policy-Manager.app"

swift build --package-path "$ROOT" -c release --disable-sandbox
BIN_DIR=$(swift build --package-path "$ROOT" -c release --disable-sandbox --show-bin-path)

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/UniFiPolicyManagerMac" "$APP/Contents/MacOS/UniFiPolicyManagerMac"
cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
cp "$REPOSITORY_ROOT/Assets/UniFi-256.png" "$APP/Contents/Resources/UniFi-256.png"
chmod +x "$APP/Contents/MacOS/UniFiPolicyManagerMac"
xattr -cr "$APP"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
echo "Built $APP"
