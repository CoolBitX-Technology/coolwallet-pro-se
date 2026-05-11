#!/bin/bash
# Build CAP files for the JavaCard applets

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"
TOOLS_JAR="$JC_LIB_DIR/tools.jar"
API_JAR="$JC_LIB_DIR/api_classic.jar"
EXPORT_DIR="$JC_LIB_DIR/api_export_files"
CLASSDIR="$PROJECT_ROOT/bin"

# Use a fixed Java 8 runtime (adjust this path on other machines)
JAVA8_HOME="/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home"
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

if [ ! -d "$CLASSDIR" ] || [ ! -f "$CLASSDIR/coolbitx/Main.class" ]; then
  echo "ERROR: Compiled classes not found in $CLASSDIR."
  echo "Please run: scripts/build.sh first."
  exit 1
fi

mkdir -p "$OUT_MAIN" "$OUT_SIO"

CP="$TOOLS_JAR:$API_JAR"

echo
echo "[1/2] Building main package (coolbitx)..."

# From .jcop and existing scripts, the AIDs are:
#   Package  AID (coolbitx)       : 'CoolWallet'      -> 43 6f 6f 6c 57 61 6c 6c 65 74
#   Applet   AID (Main applet)    : 'CoolWalletPRO'   -> 43 6f 6f 6c 57 61 6c 6c 65 74 50 52 4f

"$JAVA8" -cp "$CP" com.sun.javacard.converter.Main \
  -i \
  -verbose \
  -classdir "$CLASSDIR" \
  -d "$OUT_MAIN" \
  -exportpath "$EXPORT_DIR" \
  -applet 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74:0x50:0x52:0x4f coolbitx.Main \
  coolbitx 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74 1.0

echo
echo "[2/2] Building SIO package (coolbitx.sio)..."

# From .jcop and scripts:
#   Package  AID (coolbitx.sio)   : 'Backup'          -> 42 61 63 6b 75 70
#   Applet   AID (StoreApplet)    : 'BackupApplet'    -> 42 61 63 6b 75 70 41 70 70 6c 65 74

"$JAVA8" -cp "$CP" com.sun.javacard.converter.Main \
  -i \
  -verbose \
  -classdir "$CLASSDIR" \
  -d "$OUT_SIO" \
  -exportpath "$EXPORT_DIR" \
  -applet 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74 coolbitx.sio.StoreApplet \
  coolbitx.sio 0x42:0x61:0x63:0x6b:0x75:0x70 1.0

echo
echo "=== CAP build completed ==="
echo "Main CAP : $OUT_MAIN"
echo "SIO  CAP : $OUT_SIO"


