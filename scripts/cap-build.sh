#!/bin/bash
# Build CAP files for the JavaCard applets

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"
TOOLS_JAR="$JC_LIB_DIR/tools.jar"
API_JAR="$JC_LIB_DIR/api_classic.jar"
EXPORT_DIR="$JC_LIB_DIR/api_export_files"
CLASSDIR="$PROJECT_ROOT/bin"

# Load Java 8 home from javacard.config or environment
CONFIG_FILE="$PROJECT_ROOT/javacard.config"

if [ -z "${JAVA8_HOME:-}" ]; then
  if [ -f "$CONFIG_FILE" ]; then
    JAVA8_HOME_CFG=$(grep "^JAVA8_HOME=" "$CONFIG_FILE" | head -1 | cut -d'=' -f2-)
    if [ -n "$JAVA8_HOME_CFG" ]; then
      JAVA8_HOME="$JAVA8_HOME_CFG"
    fi
  fi
fi

if [ -z "${JAVA8_HOME:-}" ]; then
  echo "ERROR: JAVA8_HOME is not set."
  echo "Please set it in '$CONFIG_FILE' (e.g., JAVA8_HOME=/path/to/jdk8)"
  echo "or export JAVA8_HOME in your environment."
  exit 1
fi

JAVA8="$JAVA8_HOME/bin/java"

# Output locations (follow original layout as much as possible)
OUT_MAIN="$PROJECT_ROOT/bin/coolbitx/javacard"
OUT_SIO="$PROJECT_ROOT/bin/coolbitx/sio/javacard"

echo "=== Build CAP files ==="
echo "Project root : $PROJECT_ROOT"

if [ ! -d "$JC_LIB_DIR" ]; then
  echo "ERROR: $JC_LIB_DIR not found."
  echo "Please run: scripts/setup-libs.sh"
  exit 1
fi

if [ ! -f "$TOOLS_JAR" ] || [ ! -f "$API_JAR" ]; then
  echo "ERROR: tools.jar or api_classic.jar not found in $JC_LIB_DIR."
  echo "Make sure scripts/setup-libs.sh ran successfully."
  exit 1
fi

if [ ! -d "$EXPORT_DIR" ]; then
  echo "ERROR: api_export_files not found in $JC_LIB_DIR."
  echo "CAP conversion needs export files."
  exit 1
fi

echo "=== Step 1: Compile sources ==="
"$PROJECT_ROOT/scripts/build.sh"
echo

mkdir -p "$OUT_MAIN" "$OUT_SIO"

# Full classpath matching converter.sh from the JCOP SDK (tools.jar alone is not enough)
CP="$JC_LIB_DIR/tools.jar"
CP="$CP:$JC_LIB_DIR/api_classic.jar"
CP="$CP:$JC_LIB_DIR/api_classic_annotations.jar"
CP="$CP:$JC_LIB_DIR/jctasks.jar"
CP="$CP:$JC_LIB_DIR/bcel-5.2.jar"
CP="$CP:$JC_LIB_DIR/asm-all-3.1.jar"
CP="$CP:$JC_LIB_DIR/ant-contrib-1.0b3.jar"
CP="$CP:$JC_LIB_DIR/commons-cli-1.0.jar"
CP="$CP:$JC_LIB_DIR/commons-codec-1.3.jar"
CP="$CP:$JC_LIB_DIR/commons-httpclient-3.0.jar"
CP="$CP:$JC_LIB_DIR/commons-logging-1.1.jar"

CONVERTER_COMMON=(
  -Djc.home="$JC_LIB_DIR"
  -cp "$CP"
  com.sun.javacard.converter.Main
  -i
  -verbose
  -classdir "$CLASSDIR"
  -exportpath "$EXPORT_DIR"
)

echo
echo "[1/2] Building main package (coolbitx)..."

# Package  AID: 'CoolWallet'    -> 43 6f 6f 6c 57 61 6c 6c 65 74
# Applet   AID: 'CoolWalletPRO' -> 43 6f 6f 6c 57 61 6c 6c 65 74 50 52 4f

"$JAVA8" "${CONVERTER_COMMON[@]}" \
  -d "$OUT_MAIN" \
  -applet 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74:0x50:0x52:0x4f coolbitx.Main \
  coolbitx 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74 1.0

echo
echo "[2/2] Building SIO package (coolbitx.sio)..."

# Package  AID: 'Backup'        -> 42 61 63 6b 75 70
# Applet   AID: 'BackupApplet'  -> 42 61 63 6b 75 70 41 70 70 6c 65 74

"$JAVA8" "${CONVERTER_COMMON[@]}" \
  -d "$OUT_SIO" \
  -applet 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74 coolbitx.sio.StoreApplet \
  coolbitx.sio 0x42:0x61:0x63:0x6b:0x75:0x70 1.0

echo
echo "=== CAP build completed ==="
echo "Main CAP : $OUT_MAIN"
echo "SIO  CAP : $OUT_SIO"


