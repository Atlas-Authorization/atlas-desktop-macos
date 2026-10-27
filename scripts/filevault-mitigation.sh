#!/bin/bash
# FileVault and Atlas.
#
# Third-party code cannot gate the FileVault pre-boot unlock: with FileVault on, the Mac boots into a pre-boot environment that
# loads no third-party code (Apple, developer forums thread 758542), so neither this plugin nor any PAM module can run there.
# What is supported is to require Atlas at the FIRST LOGIN AFTER UNLOCK. By default macOS completes that login with the
# credentials typed into FileVault, without showing the login window; the mechanism is undocumented, so it cannot be relied on to run
# AtlasMFA:check with a verifiable password. DisableFDEAutoLogin makes the login window appear after the unlock, so the person types
# the password again and the normal login rule (system.login.console, with AtlasMFA:check in it) runs.
#
#   sudo filevault-mitigation.sh --enable | --disable | --status   [--stage DIR]
set -euo pipefail
ACTION=""; STAGE=""
while [ $# -gt 0 ]; do case "$1" in
  --enable|--disable|--status) ACTION="${1#--}";; --stage) STAGE="$2"; shift;;
  *) echo "unknown option $1" >&2; exit 2;; esac; shift; done
[ -n "$ACTION" ] || { echo "usage: filevault-mitigation.sh --enable|--disable|--status [--stage DIR]" >&2; exit 2; }
PLIST="$STAGE/Library/Preferences/com.apple.loginwindow"   # `defaults` appends .plist; a staged tree is edited with plutil
[ -n "$STAGE" ] || [ "$ACTION" = status ] || [ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
[ -z "$STAGE" ] || mkdir -p "$STAGE/Library/Preferences"

if [ -n "$STAGE" ]; then   # tests and packaging: no cfprefsd involved
  F="$PLIST.plist"
  current() { [ "$(plutil -extract DisableFDEAutoLogin raw -o - "$F" 2>/dev/null || echo false)" = true ] && echo 1 || echo 0; }
  setkey() { [ -f "$F" ] || plutil -create xml1 "$F"; plutil -replace DisableFDEAutoLogin -bool YES "$F"; }
  clearkey() { [ ! -f "$F" ] || plutil -remove DisableFDEAutoLogin "$F" 2>/dev/null || true; }
else                       # the real thing goes through defaults so cfprefsd sees it
  current() { defaults read "$PLIST" DisableFDEAutoLogin 2>/dev/null || echo 0; }
  setkey() { defaults write "$PLIST" DisableFDEAutoLogin -bool YES; }
  clearkey() { defaults delete "$PLIST" DisableFDEAutoLogin 2>/dev/null || true; }
fi
case "$ACTION" in
  enable)
    setkey
    [ "$(current)" = 1 ] || { echo "could not set DisableFDEAutoLogin" >&2; exit 1; }
    echo "DisableFDEAutoLogin is on: after the FileVault unlock the login window appears and Atlas runs."
    ;;
  disable)
    clearkey
    [ "$(current)" = 0 ] || { echo "could not clear DisableFDEAutoLogin" >&2; exit 1; }
    echo "DisableFDEAutoLogin cleared: macOS may log the person in straight after the FileVault unlock."
    ;;
esac
echo "DisableFDEAutoLogin: $([ "$(current)" = 1 ] && echo on || echo off)"
if [ -z "$STAGE" ]; then
  fdesetup status 2>/dev/null | head -1 || true
  if security authorizationdb read system.login.console 2>/dev/null | grep -q "AtlasMFA:check"; then
    echo "login rule: system.login.console contains AtlasMFA:check"
  else
    echo "WARNING: system.login.console does not contain AtlasMFA:check; run install.sh, or this setting protects nothing" >&2
  fi
  echo "Pre-boot FileVault unlock itself still takes only the disk password; Atlas cannot be added there."
fi
