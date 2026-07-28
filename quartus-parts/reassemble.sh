#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

OUT="../QuartusProSetup-part2-26.1.0.110.qdz"
PARTS=(QuartusProSetup-part2-26.1.0.110.qdz.part*)

echo "Verifying part checksums..."
sha256sum -c checksums.sha256

echo "Joining ${#PARTS[@]} parts into $OUT ..."
cat "${PARTS[@]}" > "$OUT"

echo "Verifying full file checksum..."
sha256sum -c full.sha256

echo "Done: $OUT"
