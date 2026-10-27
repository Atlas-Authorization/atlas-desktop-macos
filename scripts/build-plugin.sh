#!/bin/bash
# Builds AtlasMFA.bundle (+ atlas-sync / atlas-enroll) into $OUT (default ./build).
# Signs only when ATLAS_CODESIGN_IDENTITY is set (Developer ID Application); otherwise leaves it UNSIGNED.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/build}"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/atlas-plugin-build}"
ARCHS="${ARCHS:-arm64 x86_64}"
MIN=13.0
BUNDLE="$OUT/AtlasMFA.bundle"
rm -rf "$BUNDLE" "$SCRATCH"; mkdir -p "$BUNDLE/Contents/MacOS" "$SCRATCH" "$OUT/bin"

built=()
for a in $ARCHS; do
  # Unsupported arch on this toolchain: skip rather than fail (universal "if the toolchain allows").
  if ! clang -arch "$a" -mmacosx-version-min=$MIN -fobjc-arc -c "$ROOT/Plugin/Sources/AtlasMFA.m" -o "$SCRATCH/shim-$a.o" 2>"$SCRATCH/err-$a"; then
    echo "skipping $a: $(head -1 "$SCRATCH/err-$a")"; continue
  fi
  if ! swiftc -target "$a-apple-macos$MIN" -O -wmo -parse-as-library -module-name AtlasMFA \
      "$ROOT"/Sources/AtlasDesktopCore/*.swift "$ROOT"/Plugin/Sources/Panel.swift \
      -emit-object -o "$SCRATCH/swift-$a.o" 2>"$SCRATCH/err-$a"; then
    echo "skipping $a: swiftc failed"; tail -5 "$SCRATCH/err-$a"; [ "$a" = "$(uname -m)" ] && exit 1; continue
  fi
  clang -arch "$a" -mmacosx-version-min=$MIN -bundle -o "$SCRATCH/AtlasMFA-$a" "$SCRATCH/shim-$a.o" "$SCRATCH/swift-$a.o" \
    -L/usr/lib/swift -Wl,-rpath,/usr/lib/swift -framework AppKit -framework Security -framework Foundation -framework OpenDirectory -framework CryptoKit -framework IOKit
  built+=("$SCRATCH/AtlasMFA-$a")
done
[ ${#built[@]} -gt 0 ] || { echo "no architecture built" >&2; exit 1; }
lipo -create "${built[@]}" -output "$BUNDLE/Contents/MacOS/AtlasMFA"
cp "$ROOT/Plugin/Info.plist" "$BUNDLE/Contents/Info.plist"
plutil -lint "$BUNDLE/Contents/Info.plist" >/dev/null

# Helper CLIs (SwiftPM, host arch only unless ARCHS has both).
if [ "${SKIP_TOOLS:-0}" != 1 ]; then
  ARCHFLAGS=(); for a in $ARCHS; do ARCHFLAGS+=(--arch "$a"); done
  swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH/spm" "${ARCHFLAGS[@]}" --product atlas-sync >/dev/null
  swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH/spm" "${ARCHFLAGS[@]}" --product atlas-enroll >/dev/null
  swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH/spm" "${ARCHFLAGS[@]}" --product atlas-pam-helper >/dev/null
  BIN="$(swift build -c release --package-path "$ROOT" --scratch-path "$SCRATCH/spm" "${ARCHFLAGS[@]}" --show-bin-path)"
  cp "$BIN/atlas-sync" "$BIN/atlas-enroll" "$BIN/atlas-pam-helper" "$OUT/bin/"
  # pam_atlas.so: the same Atlas step for sshd, su, sudo and screensharing (installed separately by scripts/pam-install.sh).
  CARCH=(); for a in $ARCHS; do CARCH+=(-arch "$a"); done
  make -C "$ROOT/pam" OUT="$OUT/pam" ARCHS="${CARCH[*]}" >/dev/null
fi

if [ -n "${ATLAS_CODESIGN_IDENTITY:-}" ]; then
  for f in "$OUT"/bin/*; do [ -f "$f" ] && codesign --force --options runtime --timestamp --sign "$ATLAS_CODESIGN_IDENTITY" "$f"; done
  codesign --force --options runtime --timestamp --sign "$ATLAS_CODESIGN_IDENTITY" "$BUNDLE"
  codesign --verify --strict --verbose=2 "$BUNDLE"
  echo "signed with $ATLAS_CODESIGN_IDENTITY"
else
  echo "UNSIGNED build (set ATLAS_CODESIGN_IDENTITY to sign). An unsigned plugin is for development only."
fi
lipo -info "$BUNDLE/Contents/MacOS/AtlasMFA"
echo "built $BUNDLE"
