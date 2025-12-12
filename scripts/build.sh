#!/bin/bash
# Simple build script for the JavaCard project

set -e

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

JAVAC="$JAVA8_HOME/bin/javac"

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
  echo "If you are using Gradle, you can generate it with:"
  echo "  ./gradlew copyHostLibs"
  exit 1
fi

CLASSPATH="$API_JAR:$JCOPX_JAR:$BC_JAR"

echo "[1/2] Clean bin directory..."
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

echo "[2/2] Compile sources with Java 8 (JavaCard-compatible bytecode)..."
# JavaCard converter 3.0.5 只支援非常舊的 class 版本，
# 這裡強制 javac 使用 Java 1.3 的語法與 bytecode，避免再出現
# 「unsupported class file format of version XX」的問題。
"$JAVAC" -cp "$CLASSPATH" -source 1.6 -target 1.6 -Xlint:-options \
  -d "$BIN_DIR" $(find "$SRC_DIR" -name "*.java")

echo
echo "Build finished. Classes output to:"
echo "  $BIN_DIR"


