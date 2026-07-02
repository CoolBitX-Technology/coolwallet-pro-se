#!/bin/bash
# Compile IBM stub classes required by the TRIC JavaCard converter.
#
# TRIC (tric-1.0.jar) references 5 IBM-proprietary classes from com.ibm.jc.*
# that exist in IBM JDK but not in OpenJDK/Temurin. This script creates minimal
# stub implementations so TRIC can run on macOS without IBM JDK.
#
# Output: local_lib/javacard-libs/ibm-jc-stubs.jar

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JAR="$PROJECT_ROOT/local_lib/javacard-libs/ibm-jc-stubs.jar"

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
  exit 1
fi

JAVAC="$JAVA8_HOME/bin/javac"
JAR_TOOL="$JAVA8_HOME/bin/jar"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== Build IBM stub classes for TRIC ==="
echo "Output: $OUT_JAR"

mkdir -p "$WORK_DIR/src/com/ibm/jc"

# ── SSLCert ──────────────────────────────────────────────────────────────────
cat > "$WORK_DIR/src/com/ibm/jc/SSLCert.java" << 'EOF'
package com.ibm.jc;

public class SSLCert {
    public SSLCert() {}
}
EOF

# ── SSLRuntimeException ───────────────────────────────────────────────────────
cat > "$WORK_DIR/src/com/ibm/jc/SSLRuntimeException.java" << 'EOF'
package com.ibm.jc;

public class SSLRuntimeException extends RuntimeException {
    public SSLRuntimeException() { super(); }
    public SSLRuntimeException(String message) { super(message); }
    public SSLRuntimeException(String message, Throwable cause) { super(message, cause); }
}
EOF

# ── SSLPKCS12Token ────────────────────────────────────────────────────────────
cat > "$WORK_DIR/src/com/ibm/jc/SSLPKCS12Token.java" << 'EOF'
package com.ibm.jc;

public class SSLPKCS12Token {
    public SSLPKCS12Token() {}

    public void open(byte[] keydata, String password) {}

    public SSLCert[] getKeyRing(int keyType) {
        return new SSLCert[0];
    }
}
EOF

# ── SignedJarOutputStream ─────────────────────────────────────────────────────
# CabPkg uses this to write the CAP file (a ZIP archive).
# close(SSLCert) MUST call super.close() to finalize the ZIP structure.
cat > "$WORK_DIR/src/com/ibm/jc/SignedJarOutputStream.java" << 'EOF'
package com.ibm.jc;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class SignedJarOutputStream extends ZipOutputStream {
    public SignedJarOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void putNextEntry(ZipEntry entry) throws IOException {
        super.putNextEntry(entry);
    }

    public void close(SSLCert cert) throws IOException {
        super.close();
    }
}
EOF

# ── SignedJarInputStream ──────────────────────────────────────────────────────
# CabSign uses this to read/verify signed CAP files.
# close(SSLCert[]) returns null (no real signature verification).
cat > "$WORK_DIR/src/com/ibm/jc/SignedJarInputStream.java" << 'EOF'
package com.ibm.jc;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class SignedJarInputStream extends ZipInputStream {
    public SignedJarInputStream(InputStream in) {
        super(in);
    }

    @Override
    public ZipEntry getNextEntry() throws IOException {
        return super.getNextEntry();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return super.read(b, off, len);
    }

    @Override
    public void closeEntry() throws IOException {
        super.closeEntry();
    }

    public SSLCert close(SSLCert[] certs) throws IOException {
        super.close();
        return null;
    }
}
EOF

echo "[1/2] Compiling stub sources..."
mkdir -p "$WORK_DIR/classes"
find "$WORK_DIR/src" -name "*.java" > "$WORK_DIR/sources.txt"
"$JAVAC" -source 1.6 -target 1.6 -d "$WORK_DIR/classes" \
  $(cat "$WORK_DIR/sources.txt")

echo "[2/2] Packaging ibm-jc-stubs.jar..."
mkdir -p "$(dirname "$OUT_JAR")"
(cd "$WORK_DIR/classes" && "$JAR_TOOL" cf "$OUT_JAR" com/)

echo
echo "Created: $OUT_JAR"
echo "  $(find "$WORK_DIR/classes" -name '*.class' | wc -l | tr -d ' ') classes: $(find "$WORK_DIR/classes" -name '*.class' -exec basename {} .class \; | tr '\n' ' ')"
