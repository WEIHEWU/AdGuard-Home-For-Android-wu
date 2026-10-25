#!/bin/sh
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION_DATE="${1:-20261026}"
BETA_NUM="${2:-Beta1}"

mkdir -p "$ROOT_DIR/releases"

echo "Building Overseas Edition (海外版)..."
(
  cd "$ROOT_DIR/overseas"
  rm -f "$ROOT_DIR/releases/AdGuard_Home_For_Android_${VERSION_DATE}_${BETA_NUM}_Overseas.zip"
  zip -q -r "$ROOT_DIR/releases/AdGuard_Home_For_Android_${VERSION_DATE}_${BETA_NUM}_Overseas.zip" . -x "*.DS_Store" -x "__MACOSX/*"
)

echo "Building China Edition (国内版)..."
(
  cd "$ROOT_DIR/cn"
  rm -f "$ROOT_DIR/releases/AdGuard_Home_For_Android_${VERSION_DATE}_${BETA_NUM}_CN.zip"
  zip -q -r "$ROOT_DIR/releases/AdGuard_Home_For_Android_${VERSION_DATE}_${BETA_NUM}_CN.zip" . -x "*.DS_Store" -x "__MACOSX/*"
)

echo "Done! Packages generated in $ROOT_DIR/releases/"
ls -lh "$ROOT_DIR/releases/"
