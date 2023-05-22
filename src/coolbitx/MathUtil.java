package coolbitx;

import javacard.framework.Util;

/**
 *
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class MathUtil {

	// c = a+b mod n
	public static void addm(byte[] a, short aOff, short length, byte[] b,
			short bOff, byte[] c, short cOff, byte[] n, short nOff) {
		if ((add(a, aOff, length, b, bOff, c, cOff) != 0)
				|| (ucmp(c, cOff, n, nOff) > 0)) {
			sub(c, cOff, length, n, nOff, c, cOff);
		}
	}

	// unsigned compare
	public static short ucmp(byte[] a, short aOff, byte[] b, short bOff) {
		short ai, bi;
		for (short i = 0; i < 32; i++) {
			ai = (short) (a[(short) (aOff + i)] & 0xff);
			bi = (short) (b[(short) (bOff + i)] & 0xff);
			if (ai != bi) {
				return (short) (ai - bi);
			}
		}
		return 0;
	}

	// c = a+b
	public static short add(byte[] a, short aOff, short length, byte[] b,
			short bOff, byte[] c, short cOff) {
		short carry = 0;
		for (short i = (short) (length - 1); i >= 0; i--) {
			carry = (short) ((a[(short) (aOff + i)] & 0xFF)
					+ (b[(short) (bOff + i)] & 0xFF) + carry);
			c[(short) (cOff + i)] = (byte) carry;
			carry = (short) (carry >> 8);
		}
		return carry;
	}

	/**
	 * Assign given int to given bytes array.
	 * <code> a = value; </code>
	 * @param a bytes array.
	 * @param aOff offset of bytes array.
	 * @param value int value.
	 */
	public static void assignInt(byte[] a, short aOff, int value) {
		a[aOff] = (byte) (value >>> 24);
		a[(short) (aOff + 1)] = (byte) (value >>> 16);
		a[(short) (aOff + 2)] = (byte) (value >>> 8);
		a[(short) (aOff + 3)] = (byte) value;
	}

	private static short sub(byte[] a, short aOff, short length, byte[] b,
			short bOff, byte[] c, short cOff) {
		short ci = 0;
		for (short i = (short) (length - 1); i >= 0; i--) {
			ci = (short) ((a[(short) (aOff + i)] & 0xFF)
					- (b[(short) (bOff + i)] & 0xFF) - ci);
			c[(short) (cOff + i)] = (byte) ci;
			ci = (short) ((ci >> 8) != 0 ? 1 : 0);
		}
		return ci;
	}

	public static short ceil(short dividend, short divisor) {
		return (short) ((short) (dividend + divisor - 1) / divisor);
	}

	public static void xor(byte[] buf, short offset, short length,
			byte[] secondBuf, short secondOffset, byte[] destBuf,
			short destOffset) {
		for (short j = 0; j < length; j++) {
			destBuf[(short) (destOffset++)] = (byte) (buf[(short) (offset++)] ^ secondBuf[(short) (secondOffset++)]);
		}
	}

	static void and(byte[] buf, short offset, short length, byte[] secondBuf,
			short secondOffset, byte[] destBuf, short destOffset) {
		for (short j = 0; j < length; j++) {
			destBuf[(short) (destOffset++)] = (byte) (buf[(short) (offset++)] & secondBuf[(short) (secondOffset++)]);
		}

	}

	public static void shiftRight(byte[] buf, short offset, short length,
			byte shiftLength, byte[] destBuf, short destOffset) {

		byte shiftByte = (byte) (shiftLength / 8);
		byte shiftBit = (byte) (shiftLength % 8);
		destOffset += shiftByte;

		for (byte i = shiftByte; i < length; i++) {
			byte mask = (byte) (0xff >> shiftBit);

			destBuf[(short) (destOffset++)] += (byte) ((buf[(short) (offset)] >> shiftBit) & mask);
			if (i != (short) (length - 1)) {
				destBuf[(short) (destOffset)] += (byte) (buf[(short) (offset++)] << (8 - shiftBit));
			}
		}
	}

	public static void shiftLeftFixed(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset, byte shiftLength) {
		byte shiftByte = (byte) (shiftLength / 8);
		byte shiftBit = (byte) (shiftLength % 8);
		short workLength = (short) (length + shiftByte + 1);
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workOffset = WorkCenter.getWorkspaceOffset(workLength);

		for (byte i = 0; i < length; i++) {
			byte mask = (byte) (0xff >> (8 - shiftBit));
			workspace[(short) (workOffset + i)] += (byte) ((buf[(short) (offset)] >> (8 - shiftBit)) & mask);
			workspace[(short) (workOffset + i + 1)] += (byte) (buf[(short) (offset++)] << shiftBit);
		}

		Util.arrayCopyNonAtomic(workspace,
				(short) (workOffset + shiftByte + 1), destBuf, destOffset,
				length);
		WorkCenter.release(WorkCenter.WORK, workLength);
	}

	public static void rotl(byte[] buf, short off, short len, short shiftBit) {
		final short lenBits = (short) (32 * len);
		shiftBit = (short) ((short) (shiftBit + lenBits) % lenBits);
		// we don't care if we pass 0 or lenBits, rotr will adjust
		rotr(buf, off, len, (short) (lenBits - shiftBit));
	}

	public static void rotr(byte[] buf, short off, short len, short rot) {
		short BYTE_SIZE = 8;
		short BYTE_MASK = 0xFF;
		if (len == 0) {
			// nothing to rotate (avoid division by 0)
			return;
		}

		final short lenBits = (short) (len * BYTE_SIZE);
		// doesn't always work for edge cases close to MIN_SHORT / MAX_SHORT
		rot = (short) ((short) (rot + lenBits) % lenBits);

		// reused variables for byte and bit shift
		short shift, i;
		byte t1, t2;

		// --- byte shift
		shift = (short) (rot / BYTE_SIZE);

		// only shift when actually required
		if (shift != 0) {

			// values will never be used, src == start at the beginning
			short start = -1, src = -1, dest;

			// compiler is too stupid to see t1 will be assigned anyway
			t1 = 0;

			// go over all the bytes, but in stepwise fashion
			for (i = 0; i < len; i++) {
				// if we get back to the start
				// ... then we need to continue one position to the right
				if (src == start) {
					start++;
					t1 = buf[(short) (off + (++src))];
				}

				// calculate next location by stepping by the shift amount
				// ... modulus the length of course
				dest = (short) ((short) (src + shift) % len);

				// save value, this will be the next one to be stored
				t2 = buf[(short) (off + dest)];
				// store value, doing the actual shift
				buf[(short) (off + dest)] = t1;

				// do the step
				src = dest;
				// we're going to store t1, not t2
				t1 = t2;
			}
		}

		// --- bit shift
		shift = (short) (rot % BYTE_SIZE);

		// only shift when actually required
		if (shift != 0) {

			// t1 holds previous byte, at other side
			t1 = buf[(short) (off + len - 1)];
			for (i = 0; i < len; i++) {
				t2 = buf[(short) (off + i)];
				// take bits from previous byte and this byte together
				buf[(short) (off + i)] = (byte) ((t1 << (BYTE_SIZE - shift)) | ((t2 & BYTE_MASK) >> shift));
				// current byte is now previous byte
				t1 = t2;
			}
		}
	}

	public static void reverse(byte[] buffer, short offset, short length) {
		short changeTime = (short) (length / 2);
		for (short i = 0; i < changeTime;) {
			byte t = buffer[(short) (offset + i)];
			buffer[(short) (offset + i++)] = buffer[(short) (offset + length - i)];
			buffer[(short) (offset + length - i)] = t;
		}
	}

}
