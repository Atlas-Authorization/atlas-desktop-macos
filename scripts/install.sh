#!/bin/bash
# Installs AtlasMFA.bundle and inserts the AtlasMFA:check mechanism after builtin:authenticate.
#   sudo install.sh [--dry-run] [--bundle PATH] [--with-unlock-rule]
# Idempotent. Backs up each rule before the first change. See README "Recovery" before running on a real machine.
set -euo pipefail
DRY=0; EXTRA=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE="${ATLAS_BUNDLE:-$ROOT/build/AtlasMFA.bundle}"
BIN_SRC="${ATLAS_BIN:-$ROOT/build/bin}"
PLUGIN_DIR="${PLUGIN_DIR:-/Library/Security/SecurityAgentPlugins}"
SUPPORT="${SUPPORT_DIR:-/Library/Application Support/Atlas}"
LAUNCHD_DIR="${LAUNCHD_DIR:-/Library/LaunchDaemons}"
MECH="AtlasMFA:check"
RULES=(system.login.console)
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) DRY=1;; --with-unlock-rule) EXTRA=1;; --bundle) BUNDLE="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
[ $EXTRA = 1 ] && RULES+=(authenticate)   # opt-in: the shared "authenticate" rule (admin prompts, unlock)

[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "must run as root (or use --dry-run)" >&2; exit 1; }
[ -d "$BUNDLE" ] || { echo "bundle not found: $BUNDLE (run scripts/build-plugin.sh)" >&2; exit 1; }
[ -f "$SUPPORT/config.json" ] || echo "warning: $SUPPORT/config.json missing; enrol first (atlas-enroll) or every login will be refused (fail closed)" >&2
run() { if [ $DRY = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }

# Prints the rule plist with MECH inserted after the LAST builtin:authenticate* mechanism (no-op if present).
edit_rule() { # $1=in.plist $2=out.plist ; exit 0 changed, 10 already present, 1 error
  local in="$1" out="$2" n idx=-1 i m
  cp "$in" "$out"
  n=$(plutil -extract mechanisms raw -o - "$out" 2>/dev/null) || { echo "rule has no mechanisms array" >&2; return 1; }
  for ((i = 0; i < n; i++)); do
    m=$(plutil -extract "mechanisms.$i" raw -o - "$out")
    [ "$m" = "$MECH" ] && return 10
    case "$m" in builtin:authenticate*) idx=$i;; esac
  done
  [ $idx -ge 0 ] || { echo "no builtin:authenticate mechanism found; refusing to guess a position" >&2; return 1; }
  plutil -insert "mechanisms.$((idx + 1))" -string "$MECH" "$out"
  plutil -lint "$out" >/dev/null
  [ "$(plutil -extract "mechanisms.$((idx + 1))" raw -o - "$out")" = "$MECH" ] || { echo "verification failed" >&2; return 1; }
}

# Rules are read into temp files; nothing is written until every edit verified.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
changed=()
for r in "${RULES[@]}"; do
  security authorizationdb read "$r" > "$TMP/$r.in.plist" 2>/dev/null || { echo "cannot read rule $r" >&2; exit 1; }
  plutil -lint "$TMP/$r.in.plist" >/dev/null
  rc=0; edit_rule "$TMP/$r.in.plist" "$TMP/$r.out.plist" || rc=$?
  case $rc in 0) changed+=("$r");; 10) echo "$r: already contains $MECH";; *) exit 1;; esac
done
[ $DRY = 1 ] && for r in "${changed[@]}"; do echo "[dry-run] $r would become:"; plutil -p "$TMP/$r.out.plist" | grep -A30 mechanisms | head -30; done

run mkdir -p "$PLUGIN_DIR" "$SUPPORT/backup"
run rm -rf "$PLUGIN_DIR/AtlasMFA.bundle"
run cp -R "$BUNDLE" "$PLUGIN_DIR/AtlasMFA.bundle"
run chown -R root:wheel "$PLUGIN_DIR/AtlasMFA.bundle"
run chmod -R go-w "$PLUGIN_DIR/AtlasMFA.bundle"
if [ -d "$BIN_SRC" ]; then
  run mkdir -p /usr/local/libexec/atlas
  run cp "$BIN_SRC"/atlas-sync "$BIN_SRC"/atlas-enroll /usr/local/libexec/atlas/
  run chown root:wheel /usr/local/libexec/atlas/atlas-sync /usr/local/libexec/atlas/atlas-enroll
  run cp "$ROOT/launchd/net.atlasauth.desktop.sync.plist" "$LAUNCHD_DIR/"
  run chown root:wheel "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist"; run chmod 644 "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist"
  if [ $DRY = 0 ]; then
    launchctl bootout system "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist" 2>/dev/null || true
    launchctl bootstrap system "$LAUNCHD_DIR/net.atlasauth.desktop.sync.plist" || echo "warning: could not load LaunchDaemon" >&2
  fi
fi

for r in "${changed[@]}"; do
  bk="$SUPPORT/backup/$r.original.plist"
  [ -f "$bk" ] || run cp "$TMP/$r.in.plist" "$bk"   # keep the FIRST original; reruns never overwrite it
  if [ $DRY = 1 ]; then echo "[dry-run] security authorizationdb write $r < edited plist"
  else security authorizationdb write "$r" < "$TMP/$r.out.plist" && echo "$r: inserted $MECH"; fi
done
echo "done. Backups: $SUPPORT/backup. To undo: sudo $ROOT/scripts/uninstall.sh"
