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

echo "[1/5] Unzip JCOP plugin zip..."
unzip -q "$ZIP_PATH" -d "$TEMP_DIR/extracted"

PLUGIN_JAR="$(find "$TEMP_DIR/extracted" -name 'com.nxp.id.jcop.eclipse_*.jar' | head -1)"
if [ -z "$PLUGIN_JAR" ]; then
  echo "ERROR: JCOP Eclipse plugin jar not found in zip."
  exit 1
fi
echo "Found plugin jar: $(basename "$PLUGIN_JAR")"

echo "[2/5] Extract plugin jar..."
unzip -q "$PLUGIN_JAR" -d "$TEMP_DIR/plugin"

JTOOLS="$TEMP_DIR/plugin/JTools_Module"

echo "[3/5] Copy JavaCard 3.0.5 API, JCOPx API and tools..."

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

echo "[4/5] Copy Oracle converter jars and JCOPx export files..."

# Oracle converter (tools-1.0.jar — the actual jar Windows Eclipse + JCOP
# Tools uses, NOT a patched vanilla tools.jar) and its runtime dependencies
# (from plugin lib/). This is the full classpath used by the plugin's own
# cmds/converter.sh|.bat.
PLUGIN_LIB="$TEMP_DIR/plugin/lib"
for jar_name in ant-contrib-1.0b3.jar asm-all-3.1.jar bcel-5.2.jar \
  commons-codec-1.3.jar commons-httpclient-3.0.jar commons-logging-1.1.jar \
  jctasks-1.0.jar tools-1.0.jar; do
  if [ -f "$PLUGIN_LIB/$jar_name" ]; then
    cp "$PLUGIN_LIB/$jar_name" "$OUT_DIR/"
    echo "  Copied $jar_name"
  else
    echo "WARNING: $jar_name not found in plugin lib/"
  fi
done

# JCOPx export files (needed if applets import com.nxp.id.jcopx.* APIs)
JCOPX_SRC="$JTOOLS/JCOPx_API-R1.1.4"
if [ -d "$JCOPX_SRC" ]; then
  mkdir -p "$OUT_DIR/jcopx_export_files"
  find "$JCOPX_SRC" -name "*.exp" | while read -r exp; do
    rel="${exp#$JCOPX_SRC/}"
    dest="$OUT_DIR/jcopx_export_files/$rel"
    mkdir -p "$(dirname "$dest")"
    cp "$exp" "$dest"
  done
  echo "  Copied JCOPx export files"
else
  echo "WARNING: JCOPx_API-R1.1.4 directory not found."
fi

echo "[5/5] Download BouncyCastle (bcprov-jdk15on-1.70.jar)..."
BC_JAR="$OUT_DIR/bcprov-jdk15on-1.70.jar"
BC_URL="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar"
if [ -f "$BC_JAR" ]; then
  echo "  Already exists, skipping."
else
  curl -fsSL "$BC_URL" -o "$BC_JAR"
  echo "  Downloaded to $BC_JAR"
fi

echo
echo "Done."
echo
echo "You can now:"
echo "  1) Run: scripts/cap-build.sh       # compile + build CAP files"
echo "  2) Run: scripts/run-web-server.sh  # compile + start simulator"

rm -rf "$TEMP_DIR"


