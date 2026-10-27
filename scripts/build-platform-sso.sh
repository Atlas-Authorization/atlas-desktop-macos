#!/bin/bash
# Assembles AtlasPlatformSSO.app: the container app and the Platform SSO app extension (PlugIns/AtlasPlatformSSO.appex).
#   build-platform-sso.sh [--version X.Y.Z] [--team TEAMID] [--out DIR]
# Signing needs your Apple Developer team: the extension is only loaded when it is signed with a Developer ID (or development)
# identity whose team matches the MDM payload's TeamIdentifier, and it ships with a provisioning profile for each bundle id:
#   ATLAS_CODESIGN_IDENTITY="Developer ID Application: ..." ATLAS_PSSO_APP_PROFILE=app.provisionprofile ATLAS_PSSO_EXT_PROFILE=ext.provisionprofile \
#     build-platform-sso.sh --team TEAMID
# Without them the app is built UNSIGNED, which is what CI does: it proves the extension compiles and links as an app extension, nothing more.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${ATLAS_VERSION:-0.0.0}"; TEAM=""; OUT="${OUT:-$ROOT/build}"
while [ $# -gt 0 ]; do case "$1" in --version) VERSION="$2"; shift;; --team) TEAM="$2"; shift;; --out) OUT="$2"; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
APP="$OUT/AtlasPlatformSSO.app"; APPEX="$APP/Contents/PlugIns/AtlasPlatformSSO.appex"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APPEX/Contents/MacOS"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/atlas-psso-build}"
swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH" --product atlas-platform-sso >/dev/null
swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH" --product atlas-platform-sso-host >/dev/null
BIN="$(swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH" --show-bin-path)"
cp "$BIN/atlas-platform-sso-host" "$APP/Contents/MacOS/atlas-platform-sso-host"
cp "$BIN/atlas-platform-sso" "$APPEX/Contents/MacOS/atlas-platform-sso"
sed "s/@VERSION@/$VERSION/g" "$ROOT/PlatformSSO/Host-Info.plist" > "$APP/Contents/Info.plist"
sed "s/@VERSION@/$VERSION/g" "$ROOT/PlatformSSO/Extension-Info.plist" > "$APPEX/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" "$APPEX/Contents/Info.plist" >/dev/null
if [ -n "${ATLAS_CODESIGN_IDENTITY:-}" ] && [ -n "$TEAM" ] && [ -n "${ATLAS_PSSO_APP_PROFILE:-}" ] && [ -n "${ATLAS_PSSO_EXT_PROFILE:-}" ]; then
  EXT_ENT="$(mktemp)"; APP_ENT="$(mktemp)"; trap 'rm -f "$EXT_ENT" "$APP_ENT"' EXIT
  sed "s/@TEAM@/$TEAM/g" "$ROOT/PlatformSSO/extension-entitlements.plist.in" > "$EXT_ENT"
  sed "s/@TEAM@/$TEAM/g" "$ROOT/PlatformSSO/host-entitlements.plist.in" > "$APP_ENT"
  plutil -lint "$EXT_ENT" "$APP_ENT" >/dev/null
  cp "$ATLAS_PSSO_EXT_PROFILE" "$APPEX/Contents/embedded.provisionprofile"
  cp "$ATLAS_PSSO_APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
  codesign --force --options runtime --timestamp --entitlements "$EXT_ENT" --sign "$ATLAS_CODESIGN_IDENTITY" "$APPEX"
  codesign --force --options runtime --timestamp --entitlements "$APP_ENT" --sign "$ATLAS_CODESIGN_IDENTITY" "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
  echo "signed for team $TEAM"
else
  echo "UNSIGNED (needs ATLAS_CODESIGN_IDENTITY, --team, ATLAS_PSSO_APP_PROFILE and ATLAS_PSSO_EXT_PROFILE): macOS will not load this extension." >&2
fi
echo "built $APP"
