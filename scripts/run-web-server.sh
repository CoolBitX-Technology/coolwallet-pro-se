#!/bin/bash
# Simple runner for SimHttpServer (jCardSim-backed, no real card) on port 9527

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM_SRC_DIR="$PROJECT_ROOT/host-sim"
SIM_BIN="$PROJECT_ROOT/host-sim/bin"

# Public, version-controlled libs (e.g. jcardsim) live under lib/
PUBLIC_LIB_DIR="$PROJECT_ROOT/lib"
# Local, non-versioned JCOP / JavaCard libs live under local_lib/
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"

# Use Java 8 explicitly (jcardsim 3.x expects Java 8 / URLClassLoader)
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

JAVAC8="$JAVA8_HOME/bin/javac"
JAVA8="$JAVA8_HOME/bin/java"

# Locate jcardsim jar:
# 1) Prefer committed jar under lib/jcardsim-*.jar
# 2) Fallback to legacy location under local_lib/javacard-libs/jcardsim-*.jar
JCARDSIM_JAR="$(ls "$PUBLIC_LIB_DIR"/jcardsim-*.jar 2>/dev/null | head -1 || true)"
if [ -z "$JCARDSIM_JAR" ]; then
  JCARDSIM_JAR="$(ls "$JC_LIB_DIR"/jcardsim-*.jar 2>/dev/null | head -1 || true)"
fi
# Locate BouncyCastle provider jar (for host-side crypto)
BC_JAR="$JC_LIB_DIR/bcprov-jdk15on-1.70.jar"

if [ -z "$JCARDSIM_JAR" ] || [ ! -f "$JCARDSIM_JAR" ]; then
  echo "ERROR: jCardSim jar not found in $JC_LIB_DIR."
  echo "Please place jcardsim-*.jar under:"
  echo "  $JC_LIB_DIR/"
  exit 1
fi

if [ ! -f "$BC_JAR" ]; then
  echo "ERROR: BouncyCastle jar not found: $BC_JAR"
  echo "If you are using Gradle, you can generate it with:"
  echo "  ./gradlew copyHostLibs"
  exit 1
fi

echo "=== Step 1: Compile sources ==="
"$PROJECT_ROOT/scripts/build.sh"
echo

mkdir -p "$SIM_BIN"

echo "=== Compile host-sim sources (including SymmetricCipherImpl shadow) ==="
# Also include src/coolbitx/sim/ — excluded from the JavaCard build but needed here
SIM_SOURCES=$(find "$SIM_SRC_DIR" -name '*.java'; find "$PROJECT_ROOT/src/coolbitx/sim" -name '*.java')
"$JAVAC8" -cp "$PROJECT_ROOT/bin:$JCARDSIM_JAR:$BC_JAR" -d "$SIM_BIN" $SIM_SOURCES

echo "=== Start HTTP server on port 9527 ==="
echo "Try: curl http://localhost:9527/ping"
echo "     curl -X POST http://localhost:9527/apdu -d '80A4040009'  (raw hex, for coolwallet3-se-test)"
echo '     curl -X POST http://localhost:9527/card/sendAPDUCommand -H "Content-Type: application/json" -d '"'"'{"cla":128,"ins":84,"p1":0,"p2":0,"data":""}'"'"'  (jcvm compat)'

"$JAVA8" -cp "$SIM_BIN:$PROJECT_ROOT/bin:$JCARDSIM_JAR:$BC_JAR" SimHttpServer
