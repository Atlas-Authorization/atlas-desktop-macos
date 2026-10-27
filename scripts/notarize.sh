#!/bin/bash
# Notarises and staples a signed pkg:  notarize.sh dist/AtlasDesktopMFA-0.1.0.pkg
# Credentials (first match wins):
#   ATLAS_NOTARY_PROFILE                                   (a notarytool keychain profile)
#   ATLAS_NOTARY_KEY_ID + ATLAS_NOTARY_ISSUER + ATLAS_NOTARY_KEY_PATH   (App Store Connect API key .p8)
# With neither set the script exits 0 after saying it did nothing (an unsigned build is not notarised).
set -euo pipefail
PKG="${1:?usage: notarize.sh <pkg>}"
[ -f "$PKG" ] || { echo "no such file: $PKG" >&2; exit 1; }
case "$PKG" in *unsigned*) echo "refusing to notarise an -unsigned package"; exit 1;; esac
if [ -n "${ATLAS_NOTARY_PROFILE:-}" ]; then
  AUTH=(--keychain-profile "$ATLAS_NOTARY_PROFILE")
elif [ -n "${ATLAS_NOTARY_KEY_ID:-}" ] && [ -n "${ATLAS_NOTARY_ISSUER:-}" ] && [ -n "${ATLAS_NOTARY_KEY_PATH:-}" ]; then
  AUTH=(--key "$ATLAS_NOTARY_KEY_PATH" --key-id "$ATLAS_NOTARY_KEY_ID" --issuer "$ATLAS_NOTARY_ISSUER")
else
  echo "notary credentials not set; skipping notarisation"; exit 0
fi
xcrun notarytool submit "$PKG" "${AUTH[@]}" --wait
xcrun stapler staple "$PKG"
xcrun stapler validate "$PKG"
