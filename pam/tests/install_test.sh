#!/bin/bash
# Tests of pam-install.sh / pam-uninstall.sh against a staged filesystem (no root, nothing real is touched).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; SCRIPTS="$HERE/../../scripts"
fails=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fails=$((fails+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }

new_stage() {
  S="$(mktemp -d)"; mkdir -p "$S/etc/pam.d" "$S/Library/Application Support/Atlas"
  cat > "$S/etc/pam.d/sshd" <<'X'
# sshd: auth account password session
auth       optional       pam_krb5.so use_kcminit
auth       optional       pam_ntlm.so try_first_pass
auth       optional       pam_mount.so try_first_pass
auth       required       pam_opendirectory.so try_first_pass
account    required       pam_nologin.so
account    required       pam_sacl.so sacl_service=ssh
account    required       pam_opendirectory.so
password   required       pam_opendirectory.so
session    required       pam_launchd.so
session    optional       pam_mount.so
X
  cat > "$S/etc/pam.d/sudo" <<'X'
# sudo: auth account password session
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
X
  cat > "$S/etc/pam.d/su" <<'X'
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
X
  cat > "$S/etc/pam.d/screensharing" <<'X'
# screensharing: auth account
auth       optional       pam_krb5.so use_first_pass use_kcminit
auth       optional       pam_ntlm.so use_first_pass
auth       required       pam_opendirectory.so use_first_pass
account    required       pam_opendirectory.so
account    sufficient     pam_self.so
account    required       pam_group.so no_warn group=admin,wheel fail_safe
account    required       pam_launchd.so
X
  chmod 644 "$S"/etc/pam.d/*
  printf '{"instance_url":"https://a.example","publishable_key":"pk","instance_id":"i","device_id":"d","device_key_id":"k","enrolled":true,"break_glass_accounts":["atlas-breakglass"]}' > "$S/Library/Application Support/Atlas/config.json"
  MOD="$S/mod.so"; HLP="$S/helper"; echo mod > "$MOD"; printf '#!/bin/sh\n' > "$HLP"
  ORIG="$(mktemp -d)"; cp -p "$S"/etc/pam.d/* "$ORIG"/
}
inst() { "$SCRIPTS/pam-install.sh" --stage "$S" --module "$MOD" --helper "$HLP" "$@"; }
uninst() { "$SCRIPTS/pam-uninstall.sh" --stage "$S" "$@"; }
LINE=/usr/local/lib/pam/pam_atlas.so
cnt() { grep -cF "$LINE" "$S/etc/pam.d/$1"; }
sum() { cat "$S"/etc/pam.d/* | shasum | cut -c1-40; }

# 1. install: line once, right after the password check, the rest untouched, files placed, original kept
new_stage
inst >/dev/null 2>&1; rc=$?
check "install succeeds"                           "[ $rc = 0 ]"
for s in sshd sudo su screensharing; do check "$s: line exactly once" "[ \$(cnt $s) = 1 ]"; done
check "sshd: line follows the opendirectory auth line" "grep -A1 'auth       required       pam_opendirectory.so try_first_pass' '$S/etc/pam.d/sshd' | tail -1 | grep -qF '$LINE'"
check "sudo: smart-card line left in place"        "grep -q 'sufficient     pam_smartcard.so' '$S/etc/pam.d/sudo'"
check "su: rootok left in place"                   "grep -q 'sufficient     pam_rootok.so' '$S/etc/pam.d/su'"
check "other lines untouched (sshd)"               "diff <(grep -vF '$LINE' '$S/etc/pam.d/sshd') '$ORIG/sshd' >/dev/null"
check "module and helper installed"                "[ -x '$S/usr/local/lib/pam/pam_atlas.so' ] && [ -x '$S/usr/local/libexec/atlas/atlas-pam-helper' ]"
check "originals kept"                             "cmp -s '$S/Library/Application Support/Atlas/pam-backup/sshd.original' '$ORIG/sshd'"
check "file mode preserved"                        "[ \$(stat -f %Lp '$S/etc/pam.d/sshd') = 644 ]"

# 2. idempotent
before=$(sum); inst >/dev/null 2>&1; rc=$?
check "re-run succeeds and changes nothing"        "[ $rc = 0 ] && [ '$before' = \"\$(sum)\" ] && [ \$(cnt sshd) = 1 ]"

# 3. uninstall restores byte-identical originals, twice is fine, purge removes files
uninst >/dev/null 2>&1; rc=$?
check "uninstall succeeds"                         "[ $rc = 0 ]"
for s in sshd sudo su screensharing; do check "$s: original restored byte for byte" "cmp -s '$S/etc/pam.d/$s' '$ORIG/$s'"; done
uninst >/dev/null 2>&1; check "second uninstall is a no-op" "[ $? = 0 ]"
inst >/dev/null 2>&1; uninst --purge >/dev/null 2>&1
check "purge removes module, helper and backups"   "[ ! -e '$S/usr/local/lib/pam/pam_atlas.so' ] && [ ! -e '$S/usr/local/libexec/atlas/atlas-pam-helper' ] && [ ! -e '$S/Library/Application Support/Atlas/pam-backup' ]"

# 4. uninstall after the OS rewrote the file: only our line goes
new_stage; inst >/dev/null 2>&1
printf '# changed by an OS update\n' >> "$S/etc/pam.d/sshd"
uninst >/dev/null 2>&1
check "foreign edits survive, our line is gone"    "[ \$(cnt sshd) = 0 ] && grep -q 'changed by an OS update' '$S/etc/pam.d/sshd'"

# 5. dry run writes nothing
new_stage; before=$(sum); inst --dry-run >/dev/null 2>&1; rc=$?
check "dry run changes nothing"                    "[ $rc = 0 ] && [ '$before' = \"\$(sum)\" ] && [ ! -e '$S/usr/local/lib/pam' ]"

# 6. refusals leave EVERYTHING untouched
new_stage; printf 'auth required pam_deny.so\n' > "$S/etc/pam.d/su"; before=$(sum)
inst >/dev/null 2>&1; rc=$?
check "unrecognised layout in one file refuses all" "[ $rc != 0 ] && [ '$before' = \"\$(sum)\" ] && [ ! -e '$S/usr/local/lib/pam/pam_atlas.so' ]"

new_stage; sed -i '' 's/^auth       required       pam_opendirectory.so try_first_pass/auth       sufficient     pam_evil.so\nauth       required       pam_opendirectory.so try_first_pass/' "$S/etc/pam.d/sshd"; before=$(sum)
inst >/dev/null 2>&1; rc=$?
check "unknown sufficient module ahead is refused"  "[ $rc != 0 ] && [ '$before' = \"\$(sum)\" ]"

new_stage; printf 'auth required pam_opendirectory.so\r\n' > "$S/etc/pam.d/su"; before=$(sum)
inst >/dev/null 2>&1; check "CRLF file is refused" "[ $? != 0 ] && [ '$before' = \"\$(sum)\" ]"

new_stage; ln -sf "$S/etc/pam.d/sudo" "$S/etc/pam.d/su.link"; rm "$S/etc/pam.d/su"; ln -s "$S/etc/pam.d/sudo" "$S/etc/pam.d/su"; before=$(sum)
inst >/dev/null 2>&1; check "symlinked service file is refused" "[ $? != 0 ]"

new_stage; printf '{"instance_url":"https://a.example","publishable_key":"pk","instance_id":"i","device_id":"d","device_key_id":"k","enrolled":true}' > "$S/Library/Application Support/Atlas/config.json"; before=$(sum)
inst >/dev/null 2>&1; rc=$?
check "no break-glass account is refused"          "[ $rc != 0 ] && [ '$before' = \"\$(sum)\" ]"
inst --allow-no-break-glass >/dev/null 2>&1; check "...unless explicitly allowed" "[ $? = 0 ]"

new_stage; printf '{"instance_url":"https://a.example","publishable_key":"pk","instance_id":"i","enrolled":false,"break_glass_accounts":["bg"]}' > "$S/Library/Application Support/Atlas/config.json"
inst >/dev/null 2>&1; check "unenrolled Mac is refused" "[ $? != 0 ] && [ \$(cnt sshd) = 0 ]"

new_stage; rm "$S/Library/Application Support/Atlas/config.json"; inst >/dev/null 2>&1; check "missing config is refused" "[ $? != 0 ]"
new_stage; rm "$MOD"; inst >/dev/null 2>&1; check "missing module is refused" "[ $? != 0 ] && [ \$(cnt sshd) = 0 ]"

# 7. a failure part-way restores every file already changed
new_stage; chflags uchg "$S/etc/pam.d/su"; before=$(sum)   # su cannot be replaced; services run in order sshd, sudo, su
inst >/dev/null 2>&1; rc=$?
chflags nouchg "$S/etc/pam.d/su"
check "failure on the third file rolls back the first two" "[ $rc != 0 ] && [ '$before' = \"\$(sum)\" ] && [ \$(cnt sshd) = 0 ] && [ \$(cnt sudo) = 0 ]"

# 8. FileVault mitigation: the preference is set, read back and cleared
FV="$SCRIPTS/filevault-mitigation.sh"; FS="$(mktemp -d)"
"$FV" --stage "$FS" --enable >/dev/null 2>&1; check "filevault: enable sets DisableFDEAutoLogin" "[ \$? = 0 ] && [ \"\$(plutil -extract DisableFDEAutoLogin raw -o - '$FS/Library/Preferences/com.apple.loginwindow.plist')\" = true ]"
check "filevault: status reports on"  "'$FV' --stage '$FS' --status | grep -q 'DisableFDEAutoLogin: on'"
"$FV" --stage "$FS" --disable >/dev/null 2>&1; check "filevault: disable clears it" "'$FV' --stage '$FS' --status | grep -q 'DisableFDEAutoLogin: off'"
"$FV" --bogus >/dev/null 2>&1; check "filevault: unknown option is refused" "[ \$? = 2 ]"

[ "$fails" = 0 ] && echo "pam install tests passed" || { echo "$fails failure(s)"; exit 1; }
