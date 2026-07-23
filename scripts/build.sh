#!/bin/bash
# Simple build script for the JavaCard project
#
# Usage: build.sh [--sim]
#   --sim  Skip -bootclasspath restriction so System.out.println works (simulator only)

set -e

SIM_MODE=false
for arg in "$@"; do
  [ "$arg" = "--sim" ] && SIM_MODE=true
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
BIN_DIR="$PROJECT_ROOT/bin"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"

# Load Java 8 home from javacard.config or environment
CONFIG_FILE="$PROJECT_ROOT/javacard.config"

# Read from config if variable is not set
if [ -z "${JAVA8_HOME:-}" ]; then
  if [ -f "$CONFIG_FILE" ]; then
    # Read line starting with JAVA8_HOME=...
    # cut -d'=' -f2- handles values containing '='
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
JAVAC="$JAVA8_HOME/bin/javac"

# Prefer ECJ over javac — ECJ generates bytecode compatible with JavaCard converter 3.0.5
# for classes with large static initializers (e.g. Ed25519 curve constants)
ECJ_JAR="$(ls "$PROJECT_ROOT/lib"/ecj-*.jar 2>/dev/null | head -1 || true)"

echo "=== Build JavaCard project ==="
echo "Project root : $PROJECT_ROOT"

if [ ! -d "$JC_LIB_DIR" ]; then
  echo "ERROR: $JC_LIB_DIR not found."
  echo "Please run: scripts/setup-libs.sh"
  exit 1
fi

API_JAR="$JC_LIB_DIR/api_classic.jar"
JCOPX_JAR="$JC_LIB_DIR/JCOPx_API-R1.1.4.jar"
BC_JAR="$JC_LIB_DIR/bcprov-jdk15on-1.70.jar"

if [ ! -f "$API_JAR" ] || [ ! -f "$JCOPX_JAR" ]; then
  echo "ERROR: Required JavaCard jars not found in $JC_LIB_DIR."
  echo "Make sure scripts/setup-libs.sh ran successfully."
  exit 1
fi

if [ ! -f "$BC_JAR" ]; then
  echo "ERROR: BouncyCastle jar not found: $BC_JAR"
  echo "Run scripts/setup-libs.sh to restore it."
  exit 1
fi

CLASSPATH="$API_JAR:$JCOPX_JAR:$BC_JAR"

echo "[1/2] Clean bin directory..."
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

echo "[2/2] Compile sources with Java 8 (JavaCard-compatible bytecode)..."
# Exclude coolbitx/sim/ — simulation-only code, mirrors .classpath excluding="coolbitx/sim/"
SRC_FILES=$(find "$SRC_DIR" -name "*.java" -not -path "*/coolbitx/sim/*")
if [ -n "$ECJ_JAR" ]; then
  echo "  (using ECJ: $ECJ_JAR)"
  if [ "$SIM_MODE" = true ]; then
    echo "       (sim mode: -bootclasspath skipped)"
    "$JAVA8" -jar "$ECJ_JAR" -cp "$CLASSPATH" -source 1.5 -target 1.5 -g -nowarn \
      -d "$BIN_DIR" $SRC_FILES
  else
    "$JAVA8" -jar "$ECJ_JAR" -bootclasspath "$API_JAR:$JCOPX_JAR" -source 1.5 -target 1.5 -g -nowarn \
      -d "$BIN_DIR" $SRC_FILES
  fi
else
  echo "  (ECJ not found in lib/, falling back to javac)"
  if [ "$SIM_MODE" = true ]; then
    echo "       (sim mode: -bootclasspath skipped)"
    "$JAVAC" -cp "$CLASSPATH" -source 1.5 -target 1.5 -g -Xlint:-options -d "$BIN_DIR" $SRC_FILES
  else
    # Use -bootclasspath so the compiler sees JavaCard types as boot classes (not standard rt.jar).
    # This produces cleaner type information that the JavaCard converter can process without errors.
    "$JAVAC" -bootclasspath "$API_JAR:$JCOPX_JAR" -source 1.5 -target 1.5 -g -Xlint:-options \
      -d "$BIN_DIR" $SRC_FILES
  fi
fi

echo
echo "Build finished. Classes output to:"
echo "  $BIN_DIR"


