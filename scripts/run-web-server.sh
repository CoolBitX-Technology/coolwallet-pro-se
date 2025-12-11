#!/bin/bash
# Simple runner for SimHttpServer (jCardSim-backed, no real card) on port 9527

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM_SRC_DIR="$PROJECT_ROOT/host-sim"
SIM_BIN="$PROJECT_ROOT/host-sim/bin"
JC_LIB_DIR="$PROJECT_ROOT/local_lib/javacard-libs"

# Use Java 8 explicitly (jcardsim 3.x expects Java 8 / URLClassLoader)
JAVA8_HOME="/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home"
JAVAC8="$JAVA8_HOME/bin/javac"
JAVA8="$JAVA8_HOME/bin/java"

# Locate jcardsim jar (user keeps it in local_lib/, not in git)
JCARDSIM_JAR="$(ls "$JC_LIB_DIR"/jcardsim-*.jar 2>/dev/null | head -1 || true)"
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

# Ensure JavaCard applet classes are compiled
if [ ! -f "$PROJECT_ROOT/bin/coolbitx/Main.class" ]; then
  echo "ERROR: JavaCard classes not found in bin/. Please build the project first:"
  echo "  scripts/build.sh"
  exit 1
fi

mkdir -p "$SIM_BIN"

echo "=== Compile host-sim sources (including SymmetricCipherImpl shadow) ==="
SIM_SOURCES=$(find "$SIM_SRC_DIR" -name '*.java')
"$JAVAC8" -cp "$PROJECT_ROOT/bin:$JCARDSIM_JAR:$BC_JAR" -d "$SIM_BIN" $SIM_SOURCES

echo "=== Start HTTP server on port 9527 ==="
echo "Try: curl http://localhost:9527/ping"
echo "     curl -X POST http://localhost:9527/apdu -d '00A4040008A000000003000000'"

"$JAVA8" -cp "$SIM_BIN:$PROJECT_ROOT/bin:$JCARDSIM_JAR:$BC_JAR" SimHttpServer
