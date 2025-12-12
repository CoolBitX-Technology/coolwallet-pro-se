#!/bin/bash
# Setup script to extract JavaCard / JCOP libraries into local_lib/javacard-libs

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP_PATH="$PROJECT_ROOT/local_lib/NXP_JCOP_Plugin_5.32.0.4.zip"
TEMP_DIR="$PROJECT_ROOT/local_lib/jcop-temp"
OUT_DIR="$PROJECT_ROOT/local_lib/javacard-libs"

echo "=== Setup JavaCard / JCOP libraries ==="
echo "Project root : $PROJECT_ROOT"
echo "ZIP path     : $ZIP_PATH"

if [ ! -f "$ZIP_PATH" ]; then
  echo "ERROR: $ZIP_PATH not found."
  echo "Please put NXP_JCOP_Plugin_5.32.0.4.zip into local_lib/."
  exit 1
fi

rm -rf "$TEMP_DIR" "$OUT_DIR"
mkdir -p "$TEMP_DIR" "$OUT_DIR"

echo "[1/3] Unzip JCOP plugin zip..."
unzip -q "$ZIP_PATH" -d "$TEMP_DIR/extracted"

PLUGIN_JAR="$(find "$TEMP_DIR/extracted" -name 'com.nxp.id.jcop.eclipse_*.jar' | head -1)"
if [ -z "$PLUGIN_JAR" ]; then
  echo "ERROR: JCOP Eclipse plugin jar not found in zip."
  exit 1
fi
echo "Found plugin jar: $(basename "$PLUGIN_JAR")"

echo "[2/3] Extract plugin jar..."
unzip -q "$PLUGIN_JAR" -d "$TEMP_DIR/plugin"

JTOOLS="$TEMP_DIR/plugin/JTools_Module"

echo "[3/3] Copy JavaCard 3.0.5 API, JCOPx API and tools..."

# JavaCard 3.0.5 APIs
if [ -d "$JTOOLS/Java_Card_Classic_API-3.0.5/lib" ]; then
  cp "$JTOOLS/Java_Card_Classic_API-3.0.5/lib/"*.jar "$OUT_DIR"/
else
  echo "WARNING: Java_Card_Classic_API-3.0.5/lib not found."
fi

# JCOPx API R1.1.4
if [ -f "$JTOOLS/JCOPx_API-R1.1.4/JCOPx_API-R1.1.4.jar" ]; then
  cp "$JTOOLS/JCOPx_API-R1.1.4/JCOPx_API-R1.1.4.jar" "$OUT_DIR"/
else
  echo "WARNING: JCOPx_API-R1.1.4.jar not found."
fi

# API export files (optional – useful for converter)
if [ -d "$JTOOLS/Java_Card_Classic_API-3.0.5/api_export_files" ]; then
  cp -R "$JTOOLS/Java_Card_Classic_API-3.0.5/api_export_files" "$OUT_DIR"/api_export_files
fi

echo
echo "Done. Extracted libraries into:"
echo "  $OUT_DIR"
echo
echo "You can now:"
echo "  1) Ensure .vscode/settings.json is using local_lib/javacard-libs/**/*.jar and lib/**/*.jar"
echo "  2) (Optional) Run: ./gradlew copyHostLibs   # to download bcprov into local_lib/javacard-libs"
echo "  3) Manually download jcardsim-3.0.5.jar from GitHub and place it under:"
echo "       $PROJECT_ROOT/lib/"
echo "     （這個 jar 是公開的，可以一起 commit 到 Git repo）"
echo "  4) Run: scripts/build.sh   # to compile"

rm -rf "$TEMP_DIR"


