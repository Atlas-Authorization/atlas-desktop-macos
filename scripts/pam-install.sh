#!/bin/bash
# Installs pam_atlas.so and puts the Atlas step into the PAM stacks of sshd, sudo, su and screensharing.
#   sudo pam-install.sh [--dry-run] [--services "sshd sudo su screensharing"] [--module PATH] [--helper PATH]
#                       [--allow-no-break-glass] [--stage DIR]
# Verified layout: a service file is edited only if its stack has the expected shape (a pam_opendirectory auth line to follow,
# no unknown `sufficient` auth module ahead of it; pam_smartcard.so, a factor of its own, and pam_rootok.so, root needing no
# password to become anyone, are known and left alone). Every file is checked before any is written; each write is atomic and
# read back; if anything fails every file already changed is put back. The first original of each file is kept in
# <support>/pam-backup and never overwritten. Break-glass: refuses unless config.json lists a break-glass account, and the
# kill switch <support>/pam-disabled turns the module into a pass-through without touching /etc/pam.d.
# --stage DIR treats DIR as the root of the filesystem (tests, packaging) and needs no root.
set -euo pipefail

DRY=0; SERVICES="sshd sudo su screensharing"; STAGE=""; NOBG=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# From a source tree the build lives under build/; from the installed package it sits next to the scripts.
MODULE="${ATLAS_PAM_MODULE:-$ROOT/build/pam/pam_atlas.so}"; [ -f "$MODULE" ] || MODULE="$ROOT/pam/build/pam_atlas.so"
HELPER="${ATLAS_PAM_HELPER_BIN:-$ROOT/build/bin/atlas-pam-helper}"
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) DRY=1;; --services) SERVICES="$2"; shift;; --module) MODULE="$2"; shift;; --helper) HELPER="$2"; shift;;
  --allow-no-break-glass) NOBG=1;; --stage) STAGE="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done

P="$STAGE"                                   # filesystem prefix
PAMDIR="$P/etc/pam.d"
SUPPORT="$P/Library/Application Support/Atlas"
MODDIR="$P/usr/local/lib/pam"
LIBEXEC="$P/usr/local/libexec/atlas"
LINE_PATH="/usr/local/lib/pam/pam_atlas.so"  # what the stack file says (never the stage path)
LINE="auth       required       $LINE_PATH"
BACKUP="$SUPPORT/pam-backup"

die() { echo "pam-install: $*" >&2; exit 1; }
note() { echo "pam-install: $*"; }
[ -n "$STAGE" ] || [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "must run as root (or use --dry-run / --stage)"
for s in $SERVICES; do case "$s" in sshd|sudo|su|screensharing|authorization) ;; *) die "unsupported service $s";; esac; done

# ---- preflight: files, config, break-glass ------------------------------------------------------------------------------
[ -f "$MODULE" ] || die "module not found: $MODULE (make -C pam)"
[ -f "$HELPER" ] || die "helper not found: $HELPER (swift build -c release --product atlas-pam-helper)"
CFG="$SUPPORT/config.json"
[ -f "$CFG" ] || die "$CFG missing: enrol this Mac first (atlas-enroll), or every PAM login would be refused"
plutil -extract instance_id raw -o - "$CFG" >/dev/null 2>&1 || die "$CFG is not valid JSON or has no instance_id"
[ "$(plutil -extract enrolled raw -o - "$CFG" 2>/dev/null || echo false)" = true ] || die "this Mac is not enrolled (config.json enrolled is not true)"
BG="$(plutil -extract break_glass_accounts json -o - "$CFG" 2>/dev/null || echo '[]')"
if [ "$BG" = "[]" ] || [ -z "$BG" ]; then
  [ "$NOBG" = 1 ] || die "no break_glass_accounts in $CFG. Create a dedicated local admin and list it first (see README), or pass --allow-no-break-glass"
  note "WARNING: installing without a break-glass account"
elif [ -z "$STAGE" ]; then
  for a in $(plutil -extract break_glass_accounts json -o - "$CFG" | tr -d '[]",' ); do
    dscl . -read "/Users/$a" UniqueID >/dev/null 2>&1 || note "WARNING: break-glass account '$a' does not exist on this Mac"
  done
fi

# ---- layout check and edit ----------------------------------------------------------------------------------------------
# Prints the new contents on stdout. Return: 0 edited, 10 already installed and well placed, 1 unrecognised layout.
edit_file() { # $1=file
  local f="$1"
  [ -f "$f" ] && [ ! -L "$f" ] || { echo "$f: missing or a symlink" >&2; return 1; }
  LC_ALL=C grep -q $'\r' "$f" && { echo "$f: CRLF line endings" >&2; return 1; }
  [ "$(wc -l < "$f")" -le 200 ] || { echo "$f: unexpectedly long" >&2; return 1; }
  awk -v line="$LINE" -v lp="$LINE_PATH" '
    function fail(m) { print m > "/dev/stderr"; bad = 1; exit 1 }
    { rows[NR] = $0 }
    END {
      n = NR; od = 0; ours = 0
      for (i = 1; i <= n; i++) {
        s = rows[i]; if (s ~ /^[ \t]*#/ || s ~ /^[ \t]*$/) continue
        split(s, w, /[ \t]+/); k = 1; if (w[1] == "") k = 2
        type = w[k]; flag = w[k+1]; mod = w[k+2]
        if (index(s, lp) > 0) { ours++; ourIdx = i }
        if (type == "auth" && mod ~ /pam_opendirectory\.so$/) od = i
        if (type == "auth" && flag == "sufficient" && mod !~ /pam_smartcard\.so$/ && mod !~ /pam_rootok\.so$/ && (od == 0 || i < od) && index(s, lp) == 0) sufficientBefore = s
      }
      if (ours > 1) fail("pam_atlas.so appears more than once")
      if (od == 0) fail("no auth pam_opendirectory.so line to follow (unrecognised layout)")
      if (sufficientBefore != "") fail("an auth `sufficient` module ahead of the password check would skip Atlas: " sufficientBefore)
      if (ours == 1) { if (ourIdx <= od) fail("pam_atlas.so sits before the password check"); for (i = 1; i <= n; i++) print rows[i]; exit 10 }
      for (i = 1; i <= n; i++) { print rows[i]; if (i == od) print line }
    }' "$f"
}

check_installed() { # $1=file ; exit 0 when our line is present exactly once and after the opendirectory auth line
  awk -v lp="$LINE_PATH" '
    { if ($0 !~ /^[ \t]*#/ && $1 == "auth" && $3 ~ /pam_opendirectory\.so$/) od = NR; if (index($0, lp) > 0 && $0 !~ /^[ \t]*#/) { c++; at = NR } }
    END { exit !(c == 1 && od > 0 && at > od) }' "$1"
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CHANGED=""; ALREADY=""
for s in $SERVICES; do
  f="$PAMDIR/$s"
  if [ ! -e "$f" ]; then note "$s: no $f on this system, skipped"; continue; fi
  rc=0; edit_file "$f" > "$TMP/$s.new" 2> "$TMP/$s.err" || rc=$?
  case $rc in
    0) CHANGED="$CHANGED $s";;
    10) ALREADY="$ALREADY $s"; note "$s: already installed";;
    *) cat "$TMP/$s.err" >&2; die "$s: layout not recognised; nothing was changed";;
  esac
done
[ -n "$CHANGED$ALREADY" ] || die "none of the requested services exists in $PAMDIR"

if [ "$DRY" = 1 ]; then
  for s in $CHANGED; do note "[dry-run] $s would become:"; diff "$PAMDIR/$s" "$TMP/$s.new" || true; done
  note "[dry-run] would install $LINE_PATH and $LIBEXEC/atlas-pam-helper; nothing written"
  exit 0
fi

# ---- install files first: a stack must never name a module that is not there ---------------------------------------------------
own() { [ -n "$STAGE" ] || chown root:wheel "$@"; }
mkdir -p "$MODDIR" "$LIBEXEC" "$BACKUP"
install -m 755 "$MODULE" "$MODDIR/pam_atlas.so.new" && own "$MODDIR/pam_atlas.so.new" && mv -f "$MODDIR/pam_atlas.so.new" "$MODDIR/pam_atlas.so"
install -m 755 "$HELPER" "$LIBEXEC/atlas-pam-helper.new" && own "$LIBEXEC/atlas-pam-helper.new" && mv -f "$LIBEXEC/atlas-pam-helper.new" "$LIBEXEC/atlas-pam-helper"
[ -n "$STAGE" ] || xattr -c "$MODDIR/pam_atlas.so" "$LIBEXEC/atlas-pam-helper" 2>/dev/null || true

# ---- backups (the first original is kept for good), then all-or-nothing apply -------------------------------------------------
for s in $CHANGED; do
  [ -f "$BACKUP/$s.original" ] || cp -p "$PAMDIR/$s" "$BACKUP/$s.original"
  cp -p "$PAMDIR/$s" "$TMP/$s.undo"
done

APPLIED=""
rollback() {
  echo "pam-install: FAILED, restoring every file already changed" >&2
  for s in $APPLIED; do
    cat "$TMP/$s.undo" > "$PAMDIR/.$s.atlas-restore" && mv -f "$PAMDIR/.$s.atlas-restore" "$PAMDIR/$s" || echo "pam-install: RESTORE FAILED for $PAMDIR/$s; backup at $BACKUP/$s.original" >&2
  done
  exit 1
}
for s in $CHANGED; do
  mode="$(stat -f %Lp "$PAMDIR/$s")"
  if cat "$TMP/$s.new" > "$PAMDIR/.$s.atlas-new" && chmod "$mode" "$PAMDIR/.$s.atlas-new" && own "$PAMDIR/.$s.atlas-new" && mv -f "$PAMDIR/.$s.atlas-new" "$PAMDIR/$s"; then
    APPLIED="$APPLIED $s"
  else
    rm -f "$PAMDIR/.$s.atlas-new"
    rollback
  fi
done
for s in $CHANGED $ALREADY; do
  check_installed "$PAMDIR/$s" || { APPLIED="$CHANGED"; rollback; }
done
note "installed for:$CHANGED$ALREADY"
note "originals kept in $BACKUP; undo with pam-uninstall.sh"
note "kill switch (no /etc/pam.d edit needed): touch '$SUPPORT/pam-disabled' as root"
note "NEXT: keep a root shell open and test sudo/su/ssh from a second one before closing it."
case " $CHANGED$ALREADY " in *" sshd "*)
  note "sshd: Atlas runs in the PAM auth stack, which sshd uses for password and keyboard-interactive logins. For key-only logins add"
  note "      'AuthenticationMethods publickey,keyboard-interactive' (with UsePAM yes, KbdInteractiveAuthentication yes) to sshd_config.";; esac
case " $CHANGED$ALREADY " in *" sudo "*) note "sudo/su: pam_smartcard.so and pam_rootok.so ahead of the password check are left as they are.";; esac
exit 0
