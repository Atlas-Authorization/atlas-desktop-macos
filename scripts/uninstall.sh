#!/bin/bash
# Removes AtlasMFA: restores the original authorization rules, deletes the bundle, helpers and LaunchDaemon.
#   sudo uninstall.sh [--dry-run] [--purge]     (--data-volume PATH: Recovery-mode file cleanup only; --purge also deletes config and the offline cache)
#
# RECOVERY (login window broken / cannot log in). What macOS does when the rule names a mechanism whose plugin is
# missing or fails to load has NOT been verified by us; assume the login FAILS CLOSED (you stay at the login window).
# Pick the first path that is available:
#  1. SSH (Remote Login must have been enabled beforehand) or another admin session or the break-glass account's
#     console session (the plugin skips Atlas for accounts in break_glass_accounts):
#        sudo /usr/local/share/atlas-desktop/scripts/uninstall.sh      (or this script from the repo)
#     by hand, using the backup this installer saved:
#        sudo security authorizationdb write system.login.console < "/Library/Application Support/Atlas/backup/system.login.console.original.plist"
#        sudo rm -rf /Library/Security/SecurityAgentPlugins/AtlasMFA.bundle
#     last resort (resets to the OS default rule):  sudo security authorizationdb remove system.login.console
#  2. Recovery mode (Apple silicon: hold the power button until "Loading startup options", Options; Intel: Cmd-R):
#     Utilities > Terminal, unlock the Data volume (Disk Utility > Mount, or `diskutil apfs unlockVolume "Macintosh HD - Data"`), then
#        /path/to/uninstall.sh --data-volume "/Volumes/Macintosh HD - Data"
#     which deletes the bundle, LaunchDaemon and helpers from that volume (it does NOT touch the authorization database,
#     because authorizationdb talks to the running system). Whether the OS then boots to a normal login window with
#     a rule that still lists the missing mechanism is the unverified part; restore the rule over SSH afterwards if so.
#     The raw rule store is /var/db/auth.db (sqlite) on the Data volume; replacing it with a copy taken before install is
#     a possible but unverified recovery.
#  3. Apple silicon has no single-user mode. Intel Macs: target disk mode from another Mac gives the same file-level access as (2).
#  4. Preventive: keep SSH enabled on managed machines and keep the break-glass account (README).
set -euo pipefail
DRY=0; PURGE=0; DATAVOL=""
PLUGIN_DIR="${PLUGIN_DIR:-/Library/Security/SecurityAgentPlugins}"
SUPPORT="${SUPPORT_DIR:-/Library/Application Support/Atlas}"
LAUNCHD_DIR="${LAUNCHD_DIR:-/Library/LaunchDaemons}"
MECH="AtlasMFA:check"
while [ $# -gt 0 ]; do case "$1" in --dry-run) DRY=1;; --purge) PURGE=1;; --data-volume) DATAVOL="$2"; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "must run as root (or use --dry-run)" >&2; exit 1; }
run() { if [ $DRY = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if [ -n "$DATAVOL" ]; then   # offline cleanup from Recovery: files only, never the authorization database
  [ -d "$DATAVOL/Library" ] || { echo "$DATAVOL/Library not found" >&2; exit 1; }
  run rm -rf "$DATAVOL$PLUGIN_DIR/AtlasMFA.bundle" "$DATAVOL/usr/local/libexec/atlas" "$DATAVOL$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist"
  echo "files removed from $DATAVOL. The authorization rule still names AtlasMFA:check; restore it after boot (README: Recovery)."
  exit 0
fi

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
