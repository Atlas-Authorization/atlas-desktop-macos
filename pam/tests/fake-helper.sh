#!/bin/sh
# Stands in for atlas-pam-helper in the integration test. Scenario from $ATLAS_FAKE; speaks the same line protocol.
read -r line
case "$line" in "BEGIN "*) ;; *) exit 1;; esac
user=$(echo "$line" | cut -d' ' -f2)
case "$ATLAS_FAKE" in
  allow) echo "ALLOW fake";;
  breakglass) [ "$user" = "atlas-breakglass" ] && echo "ALLOW break-glass account" || echo "DENY not enrolled";;
  deny) echo "DENY device revoked";;
  garbage) echo "what";;
  hang) sleep 30;;
  die) exit 3;;
  totp)
    echo "CHALLENGE online=1 push=0 totp=1 offline=0 pin=0"
    n=0
    while read -r cmd arg; do
      case "$cmd" in
        CODE) n=$((n+1)); if [ "$arg" = "123456" ]; then echo OK; else echo "RETRY wrong"; fi;;
        QUIT) exit 0;;
      esac
    done;;
  push)
    echo "CHALLENGE online=1 push=1 totp=0 offline=0 pin=0"
    read -r cmd
    [ "$cmd" = PUSH ] && { echo "NUMBER 47"; sleep 0.2; echo OK; };;
  pushreject)
    echo "CHALLENGE online=1 push=1 totp=1 offline=0 pin=0"
    read -r cmd; echo "NUMBER 12"; echo "REJECT denied"
    while read -r cmd arg; do case "$cmd" in CODE) [ "$arg" = "123456" ] && echo OK || echo "RETRY";; QUIT) exit 0;; esac; done;;
  offline)
    echo "CHALLENGE online=0 push=0 totp=0 offline=1 pin=1"
    while read -r cmd pin code; do case "$cmd" in OFFLINE) [ "$pin" = "24681357" ] && [ "$code" = "123456" ] && echo OK || echo "RETRY";; QUIT) exit 0;; esac; done;;
esac
