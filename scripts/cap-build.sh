#!/bin/bash
# Build CAP files using the Oracle JavaCard converter for both packages.
#
# This matches the actual toolchain the team's Windows Eclipse + JCOP Tools
# build uses (verified via JCOP_DEBUG converter-arg tracing against a real
# Windows build, and confirmed correct on physical hardware — see memory:
# project-tric-shift-bug.md). Two things are required for this to work:
#
#   1. Sources must be compiled with -g (scripts/build.sh does this).
#      ECJ's debug info (LineNumberTable/LocalVariableTable) works around
#      an internal Oracle converter crash (InstrContainer.merge /
#      setOperandStack) on complex methods like ScriptInterpreter's opcode
#      switch. Without -g, Oracle crashes partway through the main package.
#
#   2. The real tools-1.0.jar + api_classic.jar from the JCOP Eclipse
#      plugin must be used (scripts/setup-libs.sh) — NOT a hand-patched
#      vanilla tools.jar. tools-1.0.jar is NXP's own build of the Oracle
#      converter and is the exact jar Windows Eclipse invokes.
#
# The Oracle converter unconditionally bundles the original .class files
# plus META-INF/MANIFEST.MF / javacard.xml / APPLET-INF/applet.xml into the
# output .cap whenever the package declares an -applet (confirmed by
# decompiling tools-1.0.jar: CapGen.java always builds an AppletXml when
# the package has an applet, and CapWriter.publishCommon() always embeds
# the compiled classes when present — there is no flag to suppress this).
# None of that is meaningful to the card's JCVM; it's desktop-tooling
# metadata that bloats a real ~67KB CAP to ~285KB. strip_cap() below
# removes it, keeping only the real */javacard/*.cap component entries.
#
# Prerequisites (one-time):
#   scripts/setup-libs.sh — extracts all jars (tools-1.0.jar, api_classic.jar, …)
#   scripts/build.sh      — compiles Java sources into bin/ (invoked below)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"
TOOLS_JAR="$JC_LIB_DIR/tools-1.0.jar"
API_JAR="$JC_LIB_DIR/api_classic.jar"
EXPORT_DIR="$JC_LIB_DIR/api_export_files"
JCOPX_EXPORT_DIR="$JC_LIB_DIR/jcopx_export_files"
# Older/manually-populated local_lib layouts extract the JCOPx .exp tree
# (com/nxp/id/jcopx/...) directly under $JC_LIB_DIR instead of a
# jcopx_export_files/ subfolder — fall back to that layout if present.
if [ ! -d "$JCOPX_EXPORT_DIR" ] && [ -d "$JC_LIB_DIR/com/nxp" ]; then
  JCOPX_EXPORT_DIR="$JC_LIB_DIR"
fi
CLASSDIR="$PROJECT_ROOT/bin"

# The Oracle converter runs fine under any modern JVM — no pinned JDK 8
# needed (see scripts/build.sh for why compilation itself isn't tied to one).
if [ -n "${JAVA_HOME:-}" ]; then
  JAVA8="$JAVA_HOME/bin/java"
else
  JAVA8="java"
fi

# Both converters append the package path (and a trailing "javacard"
# segment) under whatever directory is passed via -d, so pass the bin/
# root here rather than pre-building the package path ourselves — doing
# so double-nests it, e.g. bin/coolbitx/javacard/coolbitx/javacard/coolbitx.cap
# instead of bin/coolbitx/javacard/coolbitx.cap.
OUT_MAIN="$PROJECT_ROOT/bin"
OUT_SIO="$PROJECT_ROOT/bin"

echo "=== Build CAP files (Oracle converter) ==="
echo "Project root : $PROJECT_ROOT"

if [ ! -d "$JC_LIB_DIR" ]; then
  echo "ERROR: $JC_LIB_DIR not found."
  echo "Please run: scripts/setup-libs.sh"
  exit 1
fi

if [ ! -f "$TOOLS_JAR" ] || [ ! -f "$API_JAR" ]; then
  echo "ERROR: tools-1.0.jar or api_classic.jar not found in $JC_LIB_DIR."
  echo "Make sure scripts/setup-libs.sh ran successfully."
  exit 1
fi

if [ ! -d "$EXPORT_DIR" ]; then
  echo "ERROR: api_export_files not found in $JC_LIB_DIR."
  echo "CAP conversion needs export files."
  exit 1
fi

echo "=== Step 1: Compile sources (-g) ==="
"$PROJECT_ROOT/scripts/build.sh"
echo

mkdir -p "$OUT_MAIN" "$OUT_SIO"

# Full classpath matching the real converter.bat/converter.sh shipped with
# the JCOP Eclipse plugin (order doesn't matter for the JVM, but these are
# exactly the jars it uses — verified via JCOP_DEBUG arg tracing).
JARS=(
  "$JC_LIB_DIR/ant-contrib-1.0b3.jar"
  "$JC_LIB_DIR/api_classic_annotations.jar"
  "$JC_LIB_DIR/asm-all-3.1.jar"
  "$JC_LIB_DIR/bcel-5.2.jar"
  "$JC_LIB_DIR/commons-cli-1.0.jar"
  "$JC_LIB_DIR/commons-codec-1.3.jar"
  "$JC_LIB_DIR/commons-httpclient-3.0.jar"
  "$JC_LIB_DIR/commons-logging-1.1.jar"
  "$JC_LIB_DIR/jctasks-1.0.jar"
  "$TOOLS_JAR"
  "$API_JAR"
)
ORACLE_CP=""
for j in "${JARS[@]}"; do
  if [ ! -f "$j" ]; then
    echo "ERROR: $j not found. Run: scripts/setup-libs.sh"
    exit 1
  fi
  if [ -n "$ORACLE_CP" ]; then
    ORACLE_CP="$ORACLE_CP:$j"
  else
    ORACLE_CP="$j"
  fi
done

# Export path for referenced packages
EXPORT_PATH="$EXPORT_DIR"
if [ -d "$JCOPX_EXPORT_DIR" ]; then
  EXPORT_PATH="$EXPORT_PATH:$JCOPX_EXPORT_DIR"
fi

# Strips a converter-produced .cap down to just the real */javacard/*.cap
# component entries — discards META-INF/MANIFEST.MF, javacard.xml,
# applet.xml, and the original .class files the converter always embeds
# when the package declares an applet (see header comment above).
strip_cap() {
  local cap_file="$1"
  local work_dir
  work_dir="$(mktemp -d)"
  unzip -q "$cap_file" -d "$work_dir/extracted"
  (cd "$work_dir/extracted" && find . -name "*.cap") | sed 's|^\./||' > "$work_dir/entries.txt"
  rm -f "$cap_file"
  (cd "$work_dir/extracted" && zip -q -X "$cap_file" -@ < "$work_dir/entries.txt")
  rm -rf "$work_dir"
}

# AIDs:
#   Package AID  'Backup'       = 0x42:0x61:0x63:0x6b:0x75:0x70
#   Applet  AID  'BackupApplet' = 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74
#   Package AID  'CoolWallet'      = 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74
#   Applet  AID  'CoolWalletPRO'   = above + 0x50:0x52:0x4f

echo
echo "[1/2] Building SIO package (coolbitx.sio) with Oracle converter..."
"$JAVA8" -Djc.home="$JC_LIB_DIR" -cp "$ORACLE_CP" com.sun.javacard.converter.Main \
  -i -noverify -useproxyclass \
  -classdir "$CLASSDIR" \
  -d "$OUT_SIO" \
  -exportpath "$EXPORT_PATH" \
  coolbitx.sio 0x42:0x61:0x63:0x6b:0x75:0x70 1.0 \
  -applet 0x42:0x61:0x63:0x6b:0x75:0x70:0x41:0x70:0x70:0x6c:0x65:0x74 coolbitx.sio.StoreApplet

echo
echo "[2/2] Building main package (coolbitx) with Oracle converter..."
"$JAVA8" -Djc.home="$JC_LIB_DIR" -cp "$ORACLE_CP" com.sun.javacard.converter.Main \
  -i -noverify -useproxyclass \
  -classdir "$CLASSDIR" \
  -d "$OUT_MAIN" \
  -exportpath "$EXPORT_PATH:$OUT_SIO" \
  coolbitx 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74 1.0 \
  -applet 0x43:0x6f:0x6f:0x6c:0x57:0x61:0x6c:0x6c:0x65:0x74:0x50:0x52:0x4f coolbitx.Main

echo
echo "Stripping desktop-tooling metadata (MANIFEST/xml/embedded .class) from output CAPs..."
strip_cap "$OUT_MAIN/coolbitx/javacard/coolbitx.cap"
strip_cap "$OUT_SIO/coolbitx/sio/javacard/sio.cap"

echo
echo "=== CAP build completed ==="
echo "Main CAP : $OUT_MAIN/coolbitx/javacard/coolbitx.cap"
echo "SIO  CAP : $OUT_SIO/coolbitx/sio/javacard/sio.cap"
