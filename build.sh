#!/bin/sh
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION_DATE="${1:-20261111}"

mkdir -p "$ROOT_DIR/releases"

echo "Building Overseas Edition (海外版)..."
(
  cd "$ROOT_DIR/overseas"
  rm -f "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}_Overseas.zip"
  zip -q -r "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}_Overseas.zip" . -x "*.DS_Store" -x "__MACOSX/*"
)

echo "Building China Edition (国内版)..."
(
  cd "$ROOT_DIR/cn"
  rm -f "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}_CN.zip"
  zip -q -r "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}_CN.zip" . -x "*.DS_Store" -x "__MACOSX/*"
)

echo "Done! Packages generated in $ROOT_DIR/releases/"
ls -lh "$ROOT_DIR/releases/"
