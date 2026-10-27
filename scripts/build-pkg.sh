#!/bin/bash
# Builds dist/AtlasDesktopMFA[-unsigned].pkg: component pkg + productbuild distribution.
# The postinstall runs install.sh (modifies the authorization database) unless ATLAS_SKIP_RULE_EDIT=1 is placed in
# /Library/Application Support/Atlas/skip-rule-edit before installing.
#   build-pkg.sh [--sign]    --sign needs ATLAS_INSTALLER_IDENTITY (Developer ID Installer) and refuses to fake it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/build}"
DIST="${DIST:-$ROOT/dist}"
VERSION="${ATLAS_VERSION:-0.1.0}"
SIGN=0; [ "${1:-}" = "--sign" ] && SIGN=1
if [ $SIGN = 1 ] && [ -z "${ATLAS_INSTALLER_IDENTITY:-}" ]; then echo "--sign requires ATLAS_INSTALLER_IDENTITY" >&2; exit 1; fi
[ -d "$OUT/AtlasMFA.bundle" ] || { echo "run scripts/build-plugin.sh first (OUT=$OUT)" >&2; exit 1; }

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
PAY="$STAGE/payload"; SCRIPTS="$STAGE/scripts"
mkdir -p "$PAY/Library/Security/SecurityAgentPlugins" "$PAY/usr/local/libexec/atlas" "$PAY/Library/LaunchDaemons" \
         "$PAY/usr/local/share/atlas-desktop/scripts" "$PAY/usr/local/share/atlas-desktop/build" "$SCRIPTS"
cp -R "$OUT/AtlasMFA.bundle" "$PAY/Library/Security/SecurityAgentPlugins/"
cp "$OUT/bin/atlas-sync" "$OUT/bin/atlas-enroll" "$PAY/usr/local/libexec/atlas/"
cp "$ROOT/launchd/net.atlasauth.desktop.sync.plist" "$PAY/Library/LaunchDaemons/"
cp "$ROOT/scripts/install.sh" "$ROOT/scripts/uninstall.sh" "$PAY/usr/local/share/atlas-desktop/scripts/"
mkdir -p "$PAY/usr/local/share/atlas-desktop/launchd" && cp "$ROOT/launchd/"*.plist "$PAY/usr/local/share/atlas-desktop/launchd/"
cp -R "$OUT/AtlasMFA.bundle" "$PAY/usr/local/share/atlas-desktop/build/"; mkdir -p "$PAY/usr/local/share/atlas-desktop/build/bin"
cp "$OUT/bin/"* "$PAY/usr/local/share/atlas-desktop/build/bin/"

cat > "$SCRIPTS/postinstall" <<'POST'
#!/bin/bash
# Files are already in place; this inserts the mechanism into the login rule (backs up first) and starts the sync daemon.
set -e
S=/usr/local/share/atlas-desktop
SKIP="/Library/Application Support/Atlas/skip-rule-edit"
launchctl bootout system /Library/LaunchDaemons/net.atlasauth.desktop.sync.plist 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/net.atlasauth.desktop.sync.plist 2>/dev/null || true
if [ -f "$SKIP" ]; then echo "skip-rule-edit present: not touching the authorization database"; exit 0; fi
if [ ! -f "/Library/Application Support/Atlas/config.json" ]; then
  echo "Atlas is not enrolled on this Mac (no config.json): leaving the login rule unchanged. Run atlas-enroll, then $S/scripts/install.sh"
  exit 0
fi
ATLAS_BUNDLE="$S/build/AtlasMFA.bundle" ATLAS_BIN="" "$S/scripts/install.sh"
POST
chmod +x "$SCRIPTS/postinstall"
bash -n "$SCRIPTS/postinstall"

mkdir -p "$DIST"
pkgbuild --root "$PAY" --scripts "$SCRIPTS" --identifier net.atlasauth.desktop.mfa --version "$VERSION" \
         --install-location / "$STAGE/component.pkg"
cat > "$STAGE/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Atlas desktop sign-in MFA</title>
  <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
  <domains enable_localSystem="true"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" title="Atlas desktop sign-in MFA"><pkg-ref id="net.atlasauth.desktop.mfa"/></choice>
  <pkg-ref id="net.atlasauth.desktop.mfa" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
XML
if [ $SIGN = 1 ]; then
  NAME="$DIST/AtlasDesktopMFA-$VERSION.pkg"
  productbuild --distribution "$STAGE/distribution.xml" --package-path "$STAGE" --sign "$ATLAS_INSTALLER_IDENTITY" --timestamp "$NAME"
else
  NAME="$DIST/AtlasDesktopMFA-$VERSION-unsigned.pkg"
  productbuild --distribution "$STAGE/distribution.xml" --package-path "$STAGE" "$NAME"
fi
echo "built $NAME"
