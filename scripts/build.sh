#!/bin/bash
# Simple build script for the JavaCard project

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
BIN_DIR="$PROJECT_ROOT/bin"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"

# Use a fixed Java 8 installation (adjust this path on other machines)
JAVA8_HOME="/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home"
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

if [ ! -f "$API_JAR" ] || [ ! -f "$JCOPX_JAR" ]; then
  echo "ERROR: Required jars not found in $JC_LIB_DIR."
  echo "Make sure scripts/setup-libs.sh ran successfully."
  exit 1
fi

CLASSPATH="$API_JAR:$JCOPX_JAR"

echo "[1/2] Clean bin directory..."
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

echo "[2/2] Compile sources with Java 8 (JavaCard-compatible bytecode)..."
# JavaCard converter 不支援 Java 8 的 class 檔 (version 52)，
# 這裡強制 javac 輸出較舊版本的 bytecode。
"$JAVAC" -cp "$CLASSPATH" -source 1.6 -target 1.6 -Xlint:-options \
  -d "$BIN_DIR" $(find "$SRC_DIR" -name "*.java")

echo
echo "Build finished. Classes output to:"
echo "  $BIN_DIR"


