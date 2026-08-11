#!/bin/zsh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(cd "$ROOT/.." && pwd)
APP="$ROOT/dist/UniFi-Policy-Manager.app"
SIGNING_IDENTITY="${MACOS_SIGNING_IDENTITY:--}"

swift build --package-path "$ROOT" -c release --disable-sandbox
BIN_DIR=$(swift build --package-path "$ROOT" -c release --disable-sandbox --show-bin-path)

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/UniFiPolicyManagerMac" "$APP/Contents/MacOS/UniFiPolicyManagerMac"
cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
cp "$REPOSITORY_ROOT/Assets/UniFi-256.png" "$APP/Contents/Resources/UniFi-256.png"
cp "$REPOSITORY_ROOT/Presets/unifi-forward-domains-by-service.csv" "$APP/Contents/Resources/unifi-forward-domains-by-service.csv"
chmod +x "$APP/Contents/MacOS/UniFiPolicyManagerMac"
xattr -cr "$APP"

if [[ "$SIGNING_IDENTITY" == "-" ]]; then
  SIGNING_ARGUMENTS=(--force --options runtime --sign -)
  echo "Signing with an ad-hoc identity and Hardened Runtime."
else
  SIGNING_ARGUMENTS=(--force --options runtime --timestamp --sign "$SIGNING_IDENTITY")
  echo "Signing with Developer ID identity: $SIGNING_IDENTITY"
fi

codesign "${SIGNING_ARGUMENTS[@]}" "$APP/Contents/MacOS/UniFiPolicyManagerMac"
codesign "${SIGNING_ARGUMENTS[@]}" "$APP"
codesign --verify --deep --strict "$APP"
echo "Built $APP"
