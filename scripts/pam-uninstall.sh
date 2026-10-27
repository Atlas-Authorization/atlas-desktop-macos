#!/bin/bash
# Removes the Atlas step from the PAM stacks and (with --purge) the module, helper and backups.
#   sudo pam-uninstall.sh [--services "..."] [--purge] [--stage DIR] [--dry-run]
# Restores the saved original when the file still matches it plus our line; otherwise it deletes only our line. Every result
# is read back. Safe to run twice.
set -euo pipefail
DRY=0; PURGE=0; STAGE=""; SERVICES="sshd sudo su screensharing"
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) DRY=1;; --purge) PURGE=1;; --stage) STAGE="$2"; shift;; --services) SERVICES="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
P="$STAGE"; PAMDIR="$P/etc/pam.d"; SUPPORT="$P/Library/Application Support/Atlas"; BACKUP="$SUPPORT/pam-backup"
LINE_PATH="/usr/local/lib/pam/pam_atlas.so"
die() { echo "pam-uninstall: $*" >&2; exit 1; }
note() { echo "pam-uninstall: $*"; }
[ -n "$STAGE" ] || [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root (or use --dry-run / --stage)"
own() { [ -n "$STAGE" ] || chown root:wheel "$@"; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
rc_all=0
for s in $SERVICES; do
  f="$PAMDIR/$s"
  [ -f "$f" ] || continue
  grep -qF "$LINE_PATH" "$f" || { note "$s: not installed"; continue; }
  awk -v lp="$LINE_PATH" 'index($0, lp) == 0' "$f" > "$TMP/$s.stripped"
  if [ -f "$BACKUP/$s.original" ] && cmp -s "$TMP/$s.stripped" "$BACKUP/$s.original"; then how="restored the original"; else how="removed the Atlas line"; fi
  if [ "$DRY" = 1 ]; then note "[dry-run] $s: would have $how"; continue; fi
  mode="$(stat -f %Lp "$f")"
  if cat "$TMP/$s.stripped" > "$PAMDIR/.$s.atlas-new" && chmod "$mode" "$PAMDIR/.$s.atlas-new" && own "$PAMDIR/.$s.atlas-new" && mv -f "$PAMDIR/.$s.atlas-new" "$f" && ! grep -qF "$LINE_PATH" "$f"; then
    note "$s: $how"
  else
    rm -f "$PAMDIR/.$s.atlas-new"; echo "pam-uninstall: could not clean $f; edit it by hand and delete the pam_atlas.so line" >&2; rc_all=1
  fi
done
if [ "$PURGE" = 1 ] && [ "$DRY" = 0 ] && [ "$rc_all" = 0 ]; then
  rm -f "$P/usr/local/lib/pam/pam_atlas.so" "$P/usr/local/libexec/atlas/atlas-pam-helper"
  rm -rf "$BACKUP"
  note "module, helper and backups removed"
elif [ "$PURGE" = 1 ] && [ "$rc_all" != 0 ]; then
  note "files kept: a stack still names the module"
fi
exit $rc_all
