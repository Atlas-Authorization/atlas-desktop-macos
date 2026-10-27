#!/bin/sh
# Integration test: the real PAM stack, the test build of the module and a fake helper. Needs root (writes /etc/pam.d).
set -eu
OUT=${1:-build}; HERE=$(cd "$(dirname "$0")" && pwd); OUT=$(cd "$OUT" && pwd)
[ "$(id -u)" = 0 ] || { echo "itest needs root (sudo make itest)"; exit 1; }
SVC=atlas-pam-test
DIR=/usr/local/lib/pam-atlas-test
mkdir -p "$DIR" && chown root:wheel "$DIR" && chmod 755 "$DIR"
install -o root -g wheel -m 755 "$OUT/pam_atlas_test.so" "$DIR/pam_atlas_test.so"
install -o root -g wheel -m 755 "$HERE/fake-helper.sh" "$DIR/fake-helper.sh"
printf 'auth required pam_permit.so\nauth required %s/pam_atlas_test.so\naccount required pam_permit.so\n' "$DIR" > /etc/pam.d/$SVC
chown root:wheel /etc/pam.d/$SVC && chmod 644 /etc/pam.d/$SVC
trap 'rm -rf "$DIR" /etc/pam.d/$SVC' EXIT
export ATLAS_PAM_HELPER="$DIR/fake-helper.sh"
PW=atlas-test-password
fails=0
run() { # name expect(0|1) scenario user password answers...
  name=$1; expect=$2; scen=$3; user=$4; pw=$5; shift 5
  out=$(ATLAS_FAKE=$scen "$OUT/harness" $SVC "$user" "$pw" "$@" 2>&1) && rc=0 || rc=1
  if [ "$rc" = "$expect" ]; then echo "ok   $name"; else echo "FAIL $name (exit $rc, wanted $expect)"; echo "$out" | sed 's/^/     /'; fails=$((fails+1)); fi
  LAST="$out"
}
run "enrolled user allowed"                0 allow      alice $PW
run "break-glass account allowed"          0 breakglass atlas-breakglass $PW
run "other account refused by the gate"    1 breakglass alice $PW
run "gate denies"                          1 deny       alice $PW
run "wrong password never reaches helper"  1 allow      alice wrong
echo "$LAST" | grep -q PROMPT && { echo "FAIL prompted after wrong password"; fails=$((fails+1)); }
run "no password from earlier module"      1 allow      alice -
run "bad user name refused"                1 allow      'a b' $PW
run "helper garbage refused"               1 garbage    alice $PW
run "helper dies refused"                  1 die        alice $PW
run "helper hangs refused (timeout)"       1 hang       alice $PW
run "totp right"                           0 totp       alice $PW 123456
run "totp wrong x3"                        1 totp       alice $PW 111111 222222 333333
run "totp right on second try"             0 totp       alice $PW 111111 123456
run "totp prompt cancelled"                1 totp       alice $PW
run "push approved"                        0 push       alice $PW
echo "$LAST" | grep -q "pick 47" || { echo "FAIL push number not shown"; fails=$((fails+1)); }
run "push rejected then code"              0 pushreject alice $PW 123456
run "offline pin + code"                   0 offline    alice $PW 24681357 123456
run "offline wrong"                        1 offline    alice $PW 24681357 000000 24681357 000000 24681357 000000
# Kill switch (root-owned file) passes through; a non-root-owned or group-writable one is ignored.
mkdir -p "/Library/Application Support/Atlas"
touch "/Library/Application Support/Atlas/pam-disabled"; chmod 644 "/Library/Application Support/Atlas/pam-disabled"
run "kill switch passes through"           0 deny       alice $PW
chmod 666 "/Library/Application Support/Atlas/pam-disabled"
run "writable kill switch is ignored"      1 deny       alice $PW
rm -f "/Library/Application Support/Atlas/pam-disabled"
[ "$fails" = 0 ] && echo "pam integration tests passed" || { echo "$fails failure(s)"; exit 1; }
