/**
 * 
 */
package coolbitx;

import javacard.framework.ISOException;
import javacard.framework.Util;

//import javacard.framework.Util;

/**
 * 
 * @author Derek Tsai <dereku@coolbitx.com>
 * 
 */

public class NumberUtil {

	// pure binary data, like:
	// byte[2] data={0xFE,0xDC};
	public static final byte[] binaryCharset = { 0 };

	// BCD compressed binary data, like:
	// byte[3] data={0x06,0x52,0x44};
	public static final byte[] bcdCharset = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 32, 33, 34, 35, 36, 37, 38, 39,
			40, 41, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 64, 65, 66, 67, 68,
			69, 70, 71, 72, 73, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 96, 97,
			98, 99, 100, 101, 102, 103, 104, 105, 112, 113, 114, 115, 116, 117,
			118, 119, 120, 121, -128, -127, -126, -125, -124, -123, -122, -121,
			-120, -119, -112, -111, -110, -109, -108, -107, -106, -105, -104,
			-103 };

	// decimal ASCII string, like:
	// byte[5] data={'6','5','2','4','4'};
	public static final byte[] decimalCharset = { '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9' };

	// hexadecimal ASCII string, like:
	// byte[4] data={'F','E','D','C'};
	public static final byte[] hexadecimalCharset = { '0', '1', '2', '3', '4',
			'5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	public static final byte[] base32BitcoinCashCharset = { 'q', 'p', 'z', 'r',
			'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's',
			'3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a',
			'7', 'l' };

	public static final byte[] binary32Charset = { 0, 1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
			26, 27, 28, 29, 30, 31 };

	public static final byte[] base58Charset = { '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
			'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
			'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

	// Convert a big-endian number which encoded as charset format
	// into a number encoded as destCharset format.
	// The result number will be right-justified,
	// the left side will be filled with bytes represents zero in destCharset.
	// DestBuf shouldn't be same as buf.
	// Caller should provide that destBuf is long enough to store converted
	// number.
	public static void baseConvert(byte[] buf, short offset, short length,
			byte[] charset, byte[] destBuf, short destOffset, short destLength,
			byte[] destCharset) {
		baseConvert(buf, offset, length, charset, destBuf, destOffset,
				destLength, destCharset, (short) 0);
	}

	public static final short leftJustify = 0x0001;
	public static final short inBuffered = 0x0010;
	public static final short outBuffered = 0x0100;
	public static final short inLittleEndian = 0x0020;
	public static final short outLittleEndian = 0x0200;
	public static final short zeroInherit = 0x0002;
	public static final short bitLeftJustify8to5 = 0x0004;

	public static short baseConvert(byte[] buf, short offset, short length,
			byte[] charset, byte[] destBuf, short destOffset, short destLength,
			byte[] destCharset, short argument) {
		short charsetLength = (short) charset.length;
		short destCharsetLength = (short) destCharset.length;
		if (charset == binaryCharset) {
			charsetLength = 256;
		}
		if (destCharset == binaryCharset) {
			destCharsetLength = 256;
		}
		return baseConvert(buf, offset, length, charset, (short) 0,
				charsetLength, destBuf, destOffset, destLength, destCharset,
				(short) 0, destCharsetLength, argument);
	}

	public static short baseConvert(byte[] buf, short offset, short length,
			byte[] charset, short charsetOffset, short charsetLength,
			byte[] destBuf, short destOffset, short destLength,
			byte[] destCharset, short destCharsetOffset,
			short destCharsetLength, short argument) {

		if (destLength == -1) {
			destLength = (short) (length * 3);
		}
		byte[] inBuf = buf;
		short inOffset = offset;
		short inLength = length;
		byte[] outBuf = destBuf;
		short outOffset = destOffset;
		short outLength = destLength;

		if ((argument & inLittleEndian) != 0) {
			inBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
			inOffset = WorkCenter.getWorkspaceOffset(length);
			for (short i = 0; i < length; i++) {
				inBuf[(short) (inOffset + length - 1 - i)] = buf[(short) (offset + i)];
			}
			argument |= inBuffered;
		} else if ((argument & inBuffered) != 0) {
			inBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
			inOffset = WorkCenter.getWorkspaceOffset(length);
			Util.arrayCopyNonAtomic(buf, offset, inBuf, inOffset, length);
		}

		short zeroCount = 0;
		for (; zeroCount < inLength; zeroCount++) {
			if (inBuf[(short) (inOffset + zeroCount)] != charset[charsetOffset]) {
				break;
			}
		}
		inOffset += zeroCount;
		inLength -= zeroCount;
		if ((argument & zeroInherit) != 0) {
			argument |= leftJustify;
		}
		if ((argument & outLittleEndian) != 0) {
			argument |= outBuffered;
		}
		if ((argument & leftJustify) != 0) {
			argument |= outBuffered;
		}
		if ((argument & outBuffered) != 0) {
			outBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
			outOffset = WorkCenter.getWorkspaceOffset(destLength);
		}

		if (charset == destCharset && charsetOffset == destCharsetOffset
				&& charsetLength == destCharsetLength
				&& (argument & bitLeftJustify8to5) == 0) {
			if (inLength > outLength) {
				ISOException.throwIt((short) 0x6B04);
			}
			Util.arrayFillNonAtomic(outBuf, outOffset, outLength,
					destCharset[destCharsetOffset]);
			Util.arrayCopyNonAtomic(inBuf, inOffset, outBuf, (short) (outOffset
					+ outLength - inLength), inLength);
		} else {
			Util.arrayFillNonAtomic(outBuf, outOffset, outLength, (byte) 0);
			short inEndOffset = (short) (inOffset + inLength);
			short outEndOffset = (short) (outOffset + outLength);

			if (charset == binaryCharset) {
				for (short oi = inOffset; oi < inEndOffset; oi++) {
					multiplyAndAdd(outBuf, outOffset, outLength,
							destCharsetLength, charsetLength,
							(short) (inBuf[oi] & 0x00FF));
				}
			} else {
				byte[] workspace = WorkCenter
						.getWorkspaceArray(WorkCenter.WORK);
				short workOffset = WorkCenter.getWorkspaceOffset((short) 256);
				setReverseMask(workspace, workOffset, charset, charsetOffset,
						charsetLength);

				for (short oi = inOffset; oi < inEndOffset; oi++) {
					short c = (short) (workspace[(short) (workOffset + (inBuf[oi] & 0x00FF))] & 0x00FF);
					if (c >= charsetLength) {
						ISOException.throwIt((short) 0x6B01);
					}
					multiplyAndAdd(outBuf, outOffset, outLength,
							destCharsetLength, charsetLength, c);
				}
				WorkCenter.release(WorkCenter.WORK, (short) 256);
			}

			if ((argument & bitLeftJustify8to5) != 0) {
				if (charsetLength != 256 || destCharsetLength != 32) {
					ISOException.throwIt((short) 0x6B85);
				}
				short multiplier = (short) ((short) (length * 2) % 5);
				NumberUtil.multiplyAndAdd(outBuf, outOffset, outLength,
						(short) 32, (short) (1 << multiplier), (short) 0);
			}
			if (destCharset != binaryCharset) {
				for (short oi = outOffset; oi < outEndOffset; oi++) {
					outBuf[oi] = destCharset[(short) (destCharsetOffset + (outBuf[oi] & 0x00FF))];
				}
			}
		}
		if ((argument & leftJustify) != 0) {
			short i;
			short trimLength = outLength;
			if (destCharset != binaryCharset) {
				trimLength = (short) (outLength - 1);
			}
			for (i = 0; i < trimLength; i++) {
				if (outBuf[(short) (outOffset + i)] != destCharset[destCharsetOffset]) {
					break;
				}
			}
			outOffset += i;
			outLength -= i;
		}

		if ((argument & outLittleEndian) != 0) {
			for (short i = 0; i < outLength; i++) {
				destBuf[(short) (destOffset + outLength - 1 - i)] = outBuf[(short) (outOffset + i)];
			}
			destOffset += outLength;
			if ((argument & zeroInherit) != 0) {
				Util.arrayFillNonAtomic(destBuf, destOffset, zeroCount,
						destCharset[destCharsetOffset]);
				destOffset += zeroCount;
			}
			WorkCenter.release(WorkCenter.WORK, destLength);
		} else if ((argument & outBuffered) != 0) {
			if ((argument & zeroInherit) != 0) {
				if (destCharset == hexadecimalCharset) {
					zeroCount *= 2;
					zeroCount += (outLength % 2 == 0) ? 0 : 1;
				}
				Util.arrayFillNonAtomic(destBuf, destOffset, zeroCount,
						destCharset[destCharsetOffset]);
				destOffset += zeroCount;
			}
			Util.arrayCopyNonAtomic(outBuf, outOffset, destBuf, destOffset,
					outLength);
			destOffset += outLength;
			WorkCenter.release(WorkCenter.WORK, destLength);
		}
		if ((argument & inBuffered) != 0) {
			WorkCenter.release(WorkCenter.WORK, length);
		}

		return (short) (outLength + ((argument & zeroInherit) != 0 ? zeroCount
				: 0));
	}

	// buf[] = buf[]*multiplier+addend;
	public static void multiplyAndAdd(byte[] buf, short offset, short length,
			short base, short multiplier, short addend) {
		short temp = addend;
		for (short i = (short) (offset + length - 1); i >= offset; i--) {
			temp = (short) ((buf[(short) (i)] & 0x00FF) * multiplier + temp);
			buf[(short) (i)] = (byte) (temp % base);
			temp = (short) (temp / base);
		}
		if (temp != 0) {
			ISOException.throwIt((short) 0x6B03);
		}
	}

	/**
	 * https://developers.google.com/protocol-buffers/docs/encoding
	 * 
	 * @param buf
	 * @param dataOffset
	 * @param length
	 * @param destBuf
	 * @param destOffset
	 */
	public static short varint(byte[] buf, short dataOffset, short length,
			byte[] destBuf, short destOffset) {

		if (length == 0) {
			destBuf[destOffset] = (byte) 0;
			return (short) 1;
		}

		byte[] shiftBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short shiftOffset = WorkCenter.getWorkspaceOffset(length);
		byte[] compareBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short compareOffset = WorkCenter.getWorkspaceOffset(length);
		byte shiftLength = 7;
		short index = 0;

		Util.arrayCopyNonAtomic(buf, dataOffset, shiftBuf, shiftOffset, length);

		while (true) {
			byte data = (byte) (shiftBuf[(short) (shiftOffset + length - 1)] & 0x7f);
			Util.arrayFillNonAtomic(shiftBuf, shiftOffset, length, (byte) 0);
			MathUtil.shiftRight(buf, dataOffset, length, shiftLength, shiftBuf,
					shiftOffset);
			shiftLength += 7;
			short offset = (short) (destOffset + index);
			index++;

			boolean isEmpty = Util.arrayCompare(shiftBuf, shiftOffset,
					compareBuf, compareOffset, length) == 0;

			if (isEmpty) {
				destBuf[offset] = (byte) data;
				break;
			} else {
				destBuf[offset] = (byte) (data + 0x80);
			}
		}
		WorkCenter.release(WorkCenter.WORK, length);
		WorkCenter.release(WorkCenter.WORK1, length);
		return index;
	}

	/**
	 * https://substrate.dev/docs/en/knowledgebase/advanced/codec
	 * 
	 * @param buf
	 * @param offset
	 * @param length
	 * @param destBuf
	 * @param destOffset
	 */
	public static short scaleDecode(byte[] buf, short offset, byte[] destBuf,
			short destOffset) {

		byte mode = (byte) (buf[offset] & 0x03);
		short length = 0;
		short rotateBit = 2;
		switch (mode) {
		case 0:
			length = 1;
			break;
		case 1:
			length = 2;
			break;
		case 2:
			length = 4;
			break;
		case 3:
			length = (byte) ((buf[offset] >> 2) + 4);
			offset++;
			rotateBit = 0;
			break;
		default:
			// should not happen
			break;
		}

		byte[] output = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short outputOffset = WorkCenter.getWorkspaceOffset(length);
		byte reserveByte = 0;
		for (byte i = 1; i <= length; i++) {
			byte temp = buf[(short) (offset + length - i)];
			output[(short) (outputOffset + i - 1)] = (byte) (((temp & 0x00FF) >> rotateBit) | reserveByte);
			reserveByte = (byte) (temp << (8 - rotateBit));
		}
		short resultLength = removeLeadingZero(output, outputOffset, length,
				destBuf, destOffset);
		WorkCenter.release(WorkCenter.WORK1, length);
		return resultLength;
	}

	public static short scaleEncode(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset) {

		byte[] workBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short workOffset = WorkCenter.getWorkspaceOffset(length);
		length = removeLeadingZero(buf, offset, length, workBuf, workOffset);
		byte mode = 0;
		boolean verifyFirstByte = true;
		if (length <= 1) {
			mode = 0;
			if (length == 0) {
				verifyFirstByte = false;
			}
		} else if (length <= 2) {
			mode = 1;
		} else if (length <= 4) {
			mode = 2;
			if (length == 3) {
				verifyFirstByte = false;
			}
		} else {
			mode = 3;
			verifyFirstByte = false;
		}
		// for (byte i = 1; i < length; i *= 2) {
		// mode++;
		// }
		if (verifyFirstByte && ((workBuf[workOffset] & 0xC0) != 0)) {
			mode++;
		}

		short rotateBit = 2;
		short resultLength = 0;
		switch (mode) {
		case 0: // 0-0x3F
			resultLength = 1;
			break;
		case 1: // 0x40-0x3FFF
			resultLength = 2;
			break;
		case 2: // 0x4000-0x3FFFFFFF
			resultLength = 4;
			break;
		default:// 0x40000000-(2**536-1)
			mode = 3;
			resultLength = (short) (length + 1);
			rotateBit = 8;
			break;
		}
		byte[] tempDestBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short tempDestOffset = WorkCenter
				.getWorkspaceOffset((short) (length + 1));

		for (byte i = 0; i < length; i++) {
			byte temp = workBuf[(short) (workOffset + i)];
			tempDestBuf[(short) (tempDestOffset + length - i)] += (byte) ((temp & 0x00FF) >> (8 - rotateBit));
			tempDestBuf[(short) (tempDestOffset + length - i - 1)] += (byte) ((temp & 0x00FF) << rotateBit);
		}
		tempDestBuf[tempDestOffset] |= mode;
		if (mode == 3) {
			tempDestBuf[tempDestOffset] |= (byte) (length - 4) << 2;
		}
		Util.arrayFillNonAtomic(destBuf, destOffset, resultLength, (byte) 0);
		Util.arrayCopyNonAtomic(tempDestBuf, tempDestOffset, destBuf,
				destOffset, (short) (length + 1));
		WorkCenter.release(WorkCenter.WORK1, length);
		WorkCenter.release(WorkCenter.WORK1, (short) (length + 1));
		return resultLength;
	}

	private static short removeLeadingZero(byte[] buf, short offset,
			short length, byte[] destBuf, short destOffset) {
		short zeroNumber = 0;
		// leave at least one byte zero
		for (byte i = 0; i < length - 1; i++) {
			if (buf[(short) (offset + i)] != 0) {
				break;
			}
			zeroNumber++;
		}
		length -= zeroNumber;
		Util.arrayCopyNonAtomic(buf, (short) (offset + zeroNumber), destBuf,
				destOffset, length);
		return length;
	}

	private static void setReverseMask(byte[] workspace, short workOffset,
			byte[] charset, short charsetOffset, short charsetLength) {
		Util.arrayFillNonAtomic(workspace, workOffset, (short) 256, (byte) 0xFF);
		for (short i = 0; i < charsetLength; i++) {
			workspace[(short) (workOffset + (charset[(short) (charsetOffset + i)] & 0x00FF))] = (byte) i;
		}
		if (charset == hexadecimalCharset) {
			for (short i = 0; i < 6; i++) {
				workspace[(short) (workOffset + 'A' + i)] = (byte) (10 + i);
			}
		}
	}

	public static final int byteArrayToInt(byte[] bytes, short offset,
			short length) {
		int result = 0;
		for (short i = offset; i < (short) (offset + length); i++) {
			result = (result << 8) + (bytes[i] & 0xFF);
		}

		return result;
	}

	public static final void intToByteArray(int input, byte[] buf, short offset) {
		for (byte i = 0; i < 4; i++) {
			buf[(short) (offset + i)] = (byte) ((input >> (8 * (3 - i))) & 0xff);
		}
	}

	public static final byte typeInt = 0;
	public static final byte typeString = 1;
	public static final byte typeBoolean = 2;
	public static final byte typeBinary = 3;
	public static final byte typeArray = 4;
	public static final byte typeMap = 5;

	public static final byte BIN8 = (byte) 0xc4;
	public static final byte UINT8 = (byte) 0xcc;
	public static final byte FIXMAP_PREFIX = (byte) 0x80;
	public static final byte FIXARRAY_PREFIX = (byte) 0x90;
	public static final byte FIXSTR_PREFIX = (byte) 0xa0;
	public static final byte STR8 = (byte) 0xd9;
	public static final byte ARRAY16 = (byte) 0xdc;
	public static final byte MAP16 = (byte) 0xde;

	public static short messagePack(byte[] buf, short offset, short length,
			byte type, byte[] destBuf, short destOffset) {
		short resultLength = 0;
		switch (type) {
		case typeInt: // se not support minus now
			if (length == 0) { // encode 00
				destBuf[destOffset] = 0;
				resultLength = 1;
			} else if ((length == 1) && ((buf[offset] & 0x80) == 0)) {
				destBuf[destOffset] = buf[offset];
				resultLength = 1;
			} else {
				for (byte i = 0; i < 4; i++) {
					short outLen = (short) (1 << i);
					if (length <= outLen) {
						destBuf[destOffset++] = (byte) (UINT8 + i);
						// fill array
						destOffset += (outLen - length);
						Util.arrayCopyNonAtomic(buf, offset, destBuf,
								destOffset, length);
						resultLength = (short) (1 + outLen);
						break;
					}
				}

			}
			if (resultLength == 0) {
				// System.out.println("Integer too long");
				ISOException.throwIt((short) 0x6B05);
			}
			break;
		case typeString:
			if (length < 32) {
				destBuf[destOffset++] = (byte) (FIXSTR_PREFIX + length);
				Util.arrayCopyNonAtomic(buf, offset, destBuf, destOffset,
						length);
				resultLength = (short) (1 + length);
			} else {
				for (byte i = 0; i < 3; i++) { // i = 2 should never happen in
												// SE, cause the length is over
												// short
					if ((length >> (8 * (i + 1))) <= 0) {
						destBuf[destOffset++] = (byte) (STR8 + i);

						byte outLen = (byte) (1 << i);
						short encodeLen = ensureCapacity(buf, offset, length,
								destBuf, destOffset, outLen);
						destOffset += encodeLen;
						Util.arrayCopyNonAtomic(buf, offset, destBuf,
								destOffset, length);
						resultLength = (short) (1 + encodeLen + length);
						break;
					}
				}
			}
			if (resultLength == 0) {
				// System.out.println("String too long");
				ISOException.throwIt((short) 0x6B06);
			}
			break;
		case typeBoolean:
			if (length == 1) {
				if (buf[offset] == 0) {
					destBuf[destOffset] = (byte) 0xc2;
				} else {
					destBuf[destOffset] = (byte) 0xc3;
				}
				resultLength = 1;
			} else {
				ISOException.throwIt((short) 0x6B09);
			}
			break;
		case typeBinary:
			for (byte i = 0; i < 3; i++) { // i = 2 should never happen in SE,
											// cause the length is over short
				if ((length >> (8 * (i + 1))) <= 0) {
					destBuf[destOffset++] = (byte) (BIN8 + i);
					byte outLen = (byte) (1 << i);
					short encodeLen = ensureCapacity(buf, offset, length,
							destBuf, destOffset, outLen);
					destOffset += encodeLen;
					Util.arrayCopyNonAtomic(buf, offset, destBuf, destOffset,
							length);
					resultLength = (short) (1 + encodeLen + length);
					break;
				}
			}
			if (resultLength == 0) {
				ISOException.throwIt((short) 0x6B0B);
			}
			break;
		case typeArray:
			if (length < 16) {
				destBuf[destOffset++] = (byte) (FIXARRAY_PREFIX + length);
				// Util.arrayCopyNonAtomic(buf, offset, destBuf, destOffset,
				// length);
				resultLength = 1;
			} else {
				for (byte i = 1; i < 3; i++) { // i = 2 should never happen in
												// SE, cause the length is over
												// short
					if ((length >> (8 * (i + 1))) <= 0) {
						destBuf[destOffset++] = (byte) (ARRAY16 + i - 1);

						byte outLen = (byte) (1 << i);
						short encodeLen = ensureCapacity(buf, offset, length,
								destBuf, destOffset, outLen);
						resultLength = (short) (1 + encodeLen);
						break;
					}
				}
			}
			if (resultLength == 0) {
				// System.out.println("Array too long");
				ISOException.throwIt((short) 0x6B07);
			}
			break;
		case typeMap:
			if (length < 16) {
				destBuf[destOffset++] = (byte) (FIXMAP_PREFIX + length);
				// Util.arrayCopyNonAtomic(buf, offset, destBuf, destOffset,
				// length);
				resultLength = 1;
			} else {
				for (byte i = 1; i < 3; i++) { // i = 2 should never happen in
												// SE, cause the length is over
												// short
					if ((length >> (8 * (i + 1))) <= 0) {
						destBuf[destOffset++] = (byte) (MAP16 + i - 1);

						byte outLen = (byte) (1 << i);
						short encodeLen = ensureCapacity(buf, offset, length,
								destBuf, destOffset, outLen);
						resultLength = (short) (1 + encodeLen);
						break;
					}
				}
			}
			if (resultLength == 0) {
				// System.out.println("Map too long");
				ISOException.throwIt((short) 0x6B08);
			}
			break;
		default:
			ISOException.throwIt((short) 0x6B0A);
		}
		return resultLength;
	}

	private static short ensureCapacity(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset, byte destLength) {
		for (byte i = destLength; i > 0; i--) {
			destBuf[(short) (destOffset + destLength - i)] = (byte) (length >> (8 * (i - 1)));
		}
		return destLength;
	}

}
