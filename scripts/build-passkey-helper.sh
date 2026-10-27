#!/bin/bash
# Assembles AtlasPasskey.app, the helper that registers a security key as a passkey from a user session.
#   build-passkey-helper.sh --domain auth.example.com [--team TEAMID] [--out DIR]
# AuthenticationServices only lets an app use passkeys for a domain it is associated with, and that association is part of the
# app's code signature, so this app has to be built for YOUR passkey domain and signed with your Developer ID and a provisioning
# profile that carries the Associated Domains capability:
#   ATLAS_CODESIGN_IDENTITY="Developer ID Application: ..." ATLAS_PROVISIONING_PROFILE=profile.provisionprofile build-passkey-helper.sh --domain ... --team ...
# Then list the app id "<TEAMID>.net.atlasauth.desktop.passkey" in your Atlas instance's native apps (Apple app ids): Atlas serves it in
# the app-site-association file of that domain. Without all of that the app is built UNSIGNED and macOS will refuse its passkey
# requests (no application identifier); it is for development only.
# The login window cannot use this app (an authorization plugin has no entitlements of its own); it uses CTAP over USB HID instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN=""; TEAM=""; OUT="${OUT:-$ROOT/build}"
while [ $# -gt 0 ]; do case "$1" in --domain) DOMAIN="$2"; shift;; --team) TEAM="$2"; shift;; --out) OUT="$2"; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
echo "$DOMAIN" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' || { echo "--domain must be your passkey domain, for example auth.example.com" >&2; exit 2; }
APP="$OUT/AtlasPasskey.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/atlas-passkey-build}"
swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH" --product atlas-passkey >/dev/null
BIN="$(swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH" --show-bin-path)/atlas-passkey"
cp "$BIN" "$APP/Contents/MacOS/atlas-passkey"
cp "$ROOT/Passkey/Info.plist" "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
if [ -n "${ATLAS_CODESIGN_IDENTITY:-}" ] && [ -n "$TEAM" ] && [ -n "${ATLAS_PROVISIONING_PROFILE:-}" ]; then
  cp "$ATLAS_PROVISIONING_PROFILE" "$APP/Contents/embedded.provisionprofile"
  ENT="$(mktemp)"; trap 'rm -f "$ENT"' EXIT
  sed -e "s/@TEAM@/$TEAM/g" -e "s/@DOMAIN@/$DOMAIN/g" "$ROOT/Passkey/entitlements.plist.in" > "$ENT"
  plutil -lint "$ENT" >/dev/null
  codesign --force --options runtime --timestamp --entitlements "$ENT" --sign "$ATLAS_CODESIGN_IDENTITY" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
  codesign -d --entitlements - "$APP" 2>/dev/null | grep -q "webcredentials:$DOMAIN" || { echo "entitlement did not land in the signature" >&2; exit 1; }
  echo "signed for webcredentials:$DOMAIN as $TEAM.net.atlasauth.desktop.passkey"
else
  echo "UNSIGNED (needs ATLAS_CODESIGN_IDENTITY, ATLAS_PROVISIONING_PROFILE and --team): macOS will refuse its passkey requests." >&2
fi
echo "built $APP"
