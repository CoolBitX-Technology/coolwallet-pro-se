#!/bin/bash
# Build CAP files using a hybrid converter strategy:
#
#   [1/2] SIO package  — Oracle converter (tools.jar)
#           Oracle handles coolbitx.sio cleanly and produces the .exp file
#           that TRIC needs for the main package.  tools.jar is binary-patched
#           to fix InstrContainer.reset() crash (see patch-tools-jar.sh).
#
#   [2/2] Main package — IBM TRIC converter (tric-1.0.jar)
#           TRIC is used because Oracle's I2S algorithm cycles indefinitely
#           on certain short-type array-index patterns in RlpDecoder/RlpDataParser.
#           TRIC handles these patterns natively without an explicit -i flag.
#
# Prerequisites (one-time):
#   scripts/setup-libs.sh      — extracts all jars (tools.jar, tric-1.0.jar, …)
#   scripts/patch-tools-jar.sh — patches InstrContainer.reset() in tools.jar
#   scripts/build.sh           — compiles Java sources into bin/

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"
TOOLS_JAR="$JC_LIB_DIR/tools.jar"
API_JAR="$JC_LIB_DIR/api_classic.jar"
EXPORT_DIR="$JC_LIB_DIR/api_export_files"
JCOPX_EXPORT_DIR="$JC_LIB_DIR/jcopx_export_files"
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

# Auto-apply patch if needed (Oracle InstrContainer.reset() bug).
# IC_MARKER is the unique 24-byte block appended to reset() by the patch.
# IC_FIND is the original throw sequence present in a fresh tools.jar.
python3 -c "
import zipfile, sys
jar='$TOOLS_JAR'
IC = 'com/sun/javacard/converter/converters/InstrContainer.class'
IC_FIND   = bytes([0xB4,0x00,0x11,0xC7,0x00,0x0B,0xBB,0x00,0x19,0x59,0xB7,0x00,0x1A,0xBF])
IC_MARKER = bytes([0x2a,0xb4,0x00,0x10,0xc7,0x00,0x0e,
                   0x2a,0xbb,0x00,0x14,0x59,
                   0xb7,0x00,0xbb,
                   0xb5,0x00,0x10,
                   0x2a,0x01,0xb5,0x00,0x0a,0xb1])
with zipfile.ZipFile(jar) as z:
    ic = z.read(IC)
if IC_MARKER in ic:
    sys.exit(0)   # already patched
if IC_FIND in ic:
    sys.exit(1)   # needs patch
print('ERROR: InstrContainer in unexpected state — re-run scripts/setup-libs.sh to restore.')
sys.exit(2)
" 2>/dev/null
STATUS=$?
if [ $STATUS -eq 1 ]; then
  echo "tools.jar not fully patched — applying patches..."
  "$PROJECT_ROOT/scripts/patch-tools-jar.sh"
elif [ $STATUS -eq 2 ]; then
  echo "ERROR: tools.jar is in an unexpected state. Re-run scripts/setup-libs.sh to restore it."
  exit 1
fi

mkdir -p "$OUT_MAIN" "$OUT_SIO"

# Oracle converter reads $jc.home/api_export_files and $jc.home/lib/*.jar.
# javacard-libs/ already has api_export_files/ at the right level; we only
# need a lib/ subdirectory with the required jars.
JC_HOME="$JC_LIB_DIR"
JC_LIB_SUBDIR="$JC_LIB_DIR/lib"
if [ ! -d "$JC_LIB_SUBDIR" ]; then
  mkdir -p "$JC_LIB_SUBDIR"
  for jar_name in tools.jar api_classic.jar api_classic_annotations.jar api_connected.jar; do
    if [ -f "$JC_LIB_DIR/$jar_name" ]; then
      ln -sf "../$jar_name" "$JC_LIB_SUBDIR/$jar_name"
    fi
  done
fi

ORACLE_CP="$TOOLS_JAR:$API_JAR"

# TRIC classpath (IBM TRIC converter + stub classes for IBM-proprietary APIs)
TRIC_JAR="$JC_LIB_DIR/tric-1.0.jar"
IBM_STUBS="$JC_LIB_DIR/ibm-jc-stubs.jar"
ASM_JAR="$JC_LIB_DIR/asm-all-3.1.jar"
BCEL_JAR="$JC_LIB_DIR/bcel-5.2.jar"
CODEC_JAR="$JC_LIB_DIR/commons-codec-1.3.jar"

for f in "$TRIC_JAR" "$IBM_STUBS" "$ASM_JAR" "$BCEL_JAR" "$CODEC_JAR"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found. Run: scripts/setup-libs.sh"
    exit 1
  fi
done

TRIC_CP="$IBM_STUBS:$TRIC_JAR:$ASM_JAR:$BCEL_JAR:$CODEC_JAR:$API_JAR"

# Export path for referenced packages
EXPORT_PATH="$EXPORT_DIR"
if [ -d "$JCOPX_EXPORT_DIR" ]; then
  EXPORT_PATH="$EXPORT_PATH:$JCOPX_EXPORT_DIR"
fi

# Build order: SIO first (Oracle) because:
#   1. Oracle produces both .cap and .exp (TRIC only produces .cap)
#   2. TRIC needs coolbitx.sio.exp to resolve types when building main
echo
echo "[1/2] Building SIO package (coolbitx.sio) with Oracle converter..."

# AIDs:
#   Package AID  'Backup'       = 0x42:0x61:0x63:0x6b:0x75:0x70
#   Applet  AID  'BackupApplet' = 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74

"$JAVA8" -noverify -Djc.home="$JC_HOME" -cp "$ORACLE_CP" com.sun.javacard.converter.Main \
  -i \
  -classdir "$CLASSDIR" \
  -d "$OUT_SIO" \
  -exportpath "$EXPORT_PATH" \
  -applet 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74 coolbitx.sio.StoreApplet \
  coolbitx.sio 0x42:0x61:0x63:0x6b:0x75:0x70 1.0

echo
echo "[2/2] Building main package (coolbitx) with TRIC converter..."

# TRIC AID format: plain hex string (no 0x: prefix).
# CoolWallet  (pkg)    = 0x43 0x6f 0x6f 0x6c 0x57 0x61 0x6c 0x6c 0x65 0x74
# CoolWalletPRO (applet)= above + 0x50 0x52 0x4f
# -ncv : no CAP file verification (equivalent to Oracle's -noverify concern)
# OUT_SIO contains the coolbitx.sio.exp needed for cross-package type resolution

"$JAVA8" -cp "$TRIC_CP" com.ibm.jc.apps.tric.jc.Converter \
  -dd "$OUT_MAIN" \
  -cp "$CLASSDIR" \
  -ep "$EXPORT_PATH:$OUT_SIO" \
  -ncv \
  -a 436f6f6c57616c6c657450524f coolbitx.Main \
  coolbitx 436f6f6c57616c6c6574 1 0

echo
echo "=== CAP build completed ==="
echo "Main CAP : $OUT_MAIN"
echo "SIO  CAP : $OUT_SIO"
