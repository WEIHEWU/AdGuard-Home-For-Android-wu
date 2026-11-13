#!/bin/sh
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION_DATE="${1:-20261112.4}"

mkdir -p "$ROOT_DIR/releases"

echo "Building Unified Package (AdGuard-Home-GoGoGo -> AdGuard_Home_gogogo_${VERSION_DATE}.zip)..."
(
  cd "$ROOT_DIR/module"
  rm -f "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}.zip"
  zip -q -r "$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}.zip" . -x "*.DS_Store" -x "__MACOSX/*"
)

echo "Done! Package generated in $ROOT_DIR/releases/"
ls -lh "$ROOT_DIR/releases/"
