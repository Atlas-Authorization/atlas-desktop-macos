#!/bin/bash
# Removes AtlasMFA: restores the original authorization rules, deletes the bundle, helpers and LaunchDaemon.
#   sudo uninstall.sh [--dry-run] [--purge]     (--purge also deletes config and the offline cache)
#
# RECOVERY (login window broken / cannot log in):
#  * ssh in (Remote Login) or use another admin account, then:  sudo scripts/uninstall.sh
#    or by hand:   sudo rm -rf /Library/Security/SecurityAgentPlugins/AtlasMFA.bundle
#    (a rule that names a missing plugin makes the mechanism fail; the next step removes it from the rule)
#      sudo security authorizationdb write system.login.console < "/Library/Application Support/Atlas/backup/system.login.console.original.plist"
#  * Recovery mode (Cmd-R / hold power): Terminal, mount the data volume (Disk Utility -> Mount, unlock it), then:
#      rm -rf "/Volumes/<Data volume>/Library/Security/SecurityAgentPlugins/AtlasMFA.bundle"
#    authorizationdb needs a running system; deleting the bundle is the offline step, then run the
#    authorizationdb restore above after booting (or from ssh).
#  * Safe boot (hold Shift while starting) does not load third-party SecurityAgent plugins in the login rule path on all
#    versions; do not rely on it, prefer ssh or Recovery.
#  * Last resort, reset the whole rule to the system default:  sudo security authorizationdb remove system.login.console  (macOS restores built-in defaults)
set -euo pipefail
DRY=0; PURGE=0
PLUGIN_DIR="${PLUGIN_DIR:-/Library/Security/SecurityAgentPlugins}"
SUPPORT="${SUPPORT_DIR:-/Library/Application Support/Atlas}"
LAUNCHD_DIR="${LAUNCHD_DIR:-/Library/LaunchDaemons}"
MECH="AtlasMFA:check"
while [ $# -gt 0 ]; do case "$1" in --dry-run) DRY=1;; --purge) PURGE=1;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "must run as root (or use --dry-run)" >&2; exit 1; }
run() { if [ $DRY = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Authorization rules: restore the backup if present, else strip the mechanism from the live rule.
for r in system.login.console authenticate; do
  security authorizationdb read "$r" > "$TMP/cur.plist" 2>/dev/null || continue
  grep -q "$MECH" "$TMP/cur.plist" || continue
  bk="$SUPPORT/backup/$r.original.plist"
  if [ -f "$bk" ] && plutil -lint "$bk" >/dev/null 2>&1; then
    if [ $DRY = 1 ]; then echo "[dry-run] restore $r from $bk"; else security authorizationdb write "$r" < "$bk"; fi
  else
    n=$(plutil -extract mechanisms raw -o - "$TMP/cur.plist"); cp "$TMP/cur.plist" "$TMP/new.plist"
    for ((i = n - 1; i >= 0; i--)); do
      [ "$(plutil -extract "mechanisms.$i" raw -o - "$TMP/new.plist")" = "$MECH" ] && plutil -remove "mechanisms.$i" "$TMP/new.plist"
    done
    plutil -lint "$TMP/new.plist" >/dev/null
    if [ $DRY = 1 ]; then echo "[dry-run] strip $MECH from $r"; else security authorizationdb write "$r" < "$TMP/new.plist"; fi
  fi
done

if [ $DRY = 0 ]; then launchctl bootout system "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist" 2>/dev/null || true; fi
run rm -f "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist"
run rm -rf "$PLUGIN_DIR/AtlasMFA.bundle" /usr/local/libexec/atlas
[ $PURGE = 1 ] && run rm -rf "$SUPPORT"
echo "uninstalled."
