#!/bin/bash
# Patch tools.jar to fix an Oracle JavaCard converter bug:
#
# InstrContainer.reset() throws ConverterInternalError when parent_operand_stack
# is null. This happens when converting classes with large static initializers
# (e.g. Ed25519 curve constants) because setAllToChangedAndReset() calls
# resetStack() which sets both stacks to null, then reset() is called on
# those containers and throws instead of recovering.
#
# Fix: class-file surgery on InstrContainer.class:
#   1. Add Methodref pool entry for OperandStack.<init>:()V
#   2. Extend reset() Code: when parent is null, create new OperandStack()
#      if working is also null, then fall through to clear jc_instr + return.
#
# Side-effect: StackMapTable in reset() becomes inconsistent, so the converter
# must be run with `java -noverify`.
#
# Idempotent: re-running this script is safe (already-patched jars are detected).

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_JAR="$PROJECT_ROOT/local_lib/javacard-libs/tools.jar"

if [ ! -f "$TOOLS_JAR" ]; then
  echo "ERROR: $TOOLS_JAR not found. Run: scripts/setup-libs.sh"
  exit 1
fi

echo "=== Patch tools.jar (Oracle InstrContainer.reset() bug) ==="

python3 - "$TOOLS_JAR" << 'PYEOF'
import sys, zipfile, os, struct

jar_path = sys.argv[1]
IC_PATH  = 'com/sun/javacard/converter/converters/InstrContainer.class'

# Original 14-byte sequence unique to reset() in a fresh tools.jar:
#   B4 00 11  getfield parent_operand_stack (#17)
#   C7 00 0B  ifnonnull +11
#   BB 00 19  new ConverterInternalError
#   59        dup
#   B7 00 1A  invokespecial ConverterInternalError.<init>
#   BF        athrow
IC_FIND = bytes([0xB4,0x00,0x11,0xC7,0x00,0x0B,0xBB,0x00,0x19,0x59,0xB7,0x00,0x1A,0xBF])

# Applied: same prefix, but throw replaced by goto +31 (→ method offset 38,
# the new code block appended after the original 38-byte method body):
#   B4 00 11  getfield parent_operand_stack
#   C7 00 0B  ifnonnull +11
#   A7 00 1F  goto +31 (→ offset 38)
#   00 00 00 00 00  nops
IC_REPL = bytes([0xB4,0x00,0x11,0xC7,0x00,0x0B,0xA7,0x00,0x1F,0x00,0x00,0x00,0x00,0x00])

# Unique marker: 24-byte block appended to reset() when patch is applied.
# (aload_0 + getfield working + ifnonnull 56 + new OperandStack + dup +
#  invokespecial #NEW + putfield working + aload_0 + aconst_null + putfield jc_instr + return)
IC_MARKER = bytes([
    0x2a, 0xb4, 0x00, 0x10, 0xc7, 0x00, 0x0e,  # aload_0; getfield #16; ifnonnull +14
    0x2a, 0xbb, 0x00, 0x14, 0x59,               # aload_0; new #20; dup
    0xb7, 0x00, 0xbb,                            # invokespecial #187 OperandStack.<init>
    0xb5, 0x00, 0x10,                            # putfield #16 (working)
    0x2a, 0x01, 0xb5, 0x00, 0x0a,               # aload_0; null; putfield #10 (jc_instr)
    0xb1,                                        # return
])
assert len(IC_MARKER) == 24

with zipfile.ZipFile(jar_path, 'r') as z:
    ic_orig = z.read(IC_PATH)

if IC_MARKER in ic_orig:
    print("InstrContainer.reset() — already patched. Nothing to do.")
    sys.exit(0)

if IC_FIND not in ic_orig:
    print("ERROR: neither the original pattern nor the patch marker found in InstrContainer.")
    print("       Wrong tools.jar version, or jar is in an unexpected state.")
    sys.exit(1)

print("InstrContainer.reset() — applying patch...")

# ── Step 1: Apply the 14-byte in-place replacement (throw → goto 38) ────────
ic = bytearray(ic_orig.replace(IC_FIND, IC_REPL, 1))

# ── Step 2: Parse the pool to find where it ends ────────────────────────────
def u1(p): return ic[p]
def u2(p): return struct.unpack_from('>H', ic, p)[0]
def u4(p): return struct.unpack_from('>I', ic, p)[0]

pos = 8
cp_count = u2(pos); pos += 2
utf8_vals = {}
i = 1
while i < cp_count:
    tag = u1(pos)
    if tag == 1:
        length = u2(pos+1)
        utf8_vals[i] = ic[pos+3:pos+3+length].decode('utf-8', errors='replace')
        pos += 3 + length
    elif tag in (7, 8):
        pos += 3
    elif tag in (9, 10, 11, 12):
        pos += 5
    elif tag in (3, 4):
        pos += 5
    elif tag in (5, 6):
        pos += 9; i += 1
    else:
        print(f"ERROR: unknown pool tag {tag} at entry #{i}")
        sys.exit(1)
    i += 1
pool_end = pos

# ── Step 3: Find reset() Code attribute by scanning methods ─────────────────
# Skip access_flags, this_class, super_class + interfaces
pos = pool_end + 6
iface_count = u2(pos); pos += 2 + iface_count * 2

# Skip fields
field_count = u2(pos); pos += 2
for _ in range(field_count):
    pos += 6
    attr_count = u2(pos); pos += 2
    for _ in range(attr_count):
        pos += 2; pos += 4 + u4(pos-2)  # skip attribute_length + body

# Scan methods
method_count = u2(pos); pos += 2
code_attr_offset = None
for _ in range(method_count):
    m_name = utf8_vals.get(u2(pos+2), '')
    m_desc = utf8_vals.get(u2(pos+4), '')
    attr_count = u2(pos+6); pos += 8
    for _ in range(attr_count):
        a_name = utf8_vals.get(u2(pos), '')
        a_len  = u4(pos+2)
        if m_name == 'reset' and m_desc == '()V' and a_name == 'Code':
            code_attr_offset = pos
        pos += 6 + a_len

if code_attr_offset is None:
    print("ERROR: could not find reset()V Code attribute")
    sys.exit(1)

# Code attribute layout:
#   [+0] u2 attribute_name_index
#   [+2] u4 attribute_length
#   [+6] u2 max_stack
#   [+8] u2 max_locals
#   [+10] u4 code_length
#   [+14] u1 code[code_length]
attr_len_field  = code_attr_offset + 2
max_stack_field = code_attr_offset + 6
code_len_field  = code_attr_offset + 10
code_start      = code_attr_offset + 14

orig_attr_len  = u4(attr_len_field)
orig_code_len  = u4(code_len_field)
orig_max_stack = u2(max_stack_field)

# Sanity-check: reset() code must end with 'return' (0xb1)
assert ic[code_start + orig_code_len - 1] == 0xb1, "reset() doesn't end with return"

# ── Step 4: Insert new pool entry at pool_end ────────────────────────────────
# Methodref(class_index=#20, nat_index=#136) = OperandStack."<init>":()V
# #20 = Class OperandStack, #136 = NameAndType "<init>":()V
NEW_POOL = bytes([0x0a, 0x00, 0x14, 0x00, 0x88])
NEW_POOL_IDX = cp_count  # will be 187 for a fresh jar
ic = ic[:pool_end] + NEW_POOL + ic[pool_end:]
struct.pack_into('>H', ic, 8, cp_count + 1)
SHIFT = len(NEW_POOL)  # all subsequent offsets shift by this

# Recalculate shifted offsets
attr_len_field  += SHIFT
max_stack_field += SHIFT
code_len_field  += SHIFT
code_start      += SHIFT

# Update IC_MARKER with actual pool index (if jar isn't standard 187, adjust here)
# For pool index values < 256: 3rd byte of invokespecial is the index
# IC_MARKER has hardcoded 0xbb (=187) for the pool index.
# If NEW_POOL_IDX != 187, we need to update the marker bytes.
if NEW_POOL_IDX > 255:
    print(f"ERROR: new pool index {NEW_POOL_IDX} > 255, need 3-byte encoding update")
    sys.exit(1)
marker = bytearray(IC_MARKER)
# invokespecial is at marker[12:15]: b7 00 bb
marker[14] = NEW_POOL_IDX & 0xFF
marker[13] = (NEW_POOL_IDX >> 8) & 0xFF

# ── Step 5: Append new Code bytes after existing code body ──────────────────
code_end_in_file = code_start + orig_code_len
ic = ic[:code_end_in_file] + bytes(marker) + ic[code_end_in_file:]

# ── Step 6: Update code_length, attribute_length, max_stack ─────────────────
struct.pack_into('>I', ic, code_len_field, orig_code_len + len(marker))
struct.pack_into('>I', ic, attr_len_field, orig_attr_len + len(marker))
struct.pack_into('>H', ic, max_stack_field, max(orig_max_stack, 3))

# ── Step 7: Verify marker is present ────────────────────────────────────────
if bytes(marker) not in bytes(ic):
    print("ERROR: patch marker not found after patching — something went wrong")
    sys.exit(1)

# ── Step 8: Write back ───────────────────────────────────────────────────────
tmp = jar_path + '.tmp'
with zipfile.ZipFile(jar_path, 'r') as zin:
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == IC_PATH:
                zout.writestr(item, bytes(ic))
            else:
                zout.writestr(item, zin.read(item.filename))

os.replace(tmp, jar_path)
print(f"Patched: {jar_path}")
print("Note: run Oracle converter with `java -noverify` (StackMapTable inconsistency).")
PYEOF
