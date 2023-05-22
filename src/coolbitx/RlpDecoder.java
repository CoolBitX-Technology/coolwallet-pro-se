package coolbitx;

import javacard.framework.Util;
import javacard.security.CryptoException;

/**
 * Recursive Length Prefix (RLP) decoder.
 *
 * <p>
 * For the specification, refer to p16 of the <a
 * href="http://gavwood.com/paper.pdf">yellow paper</a> and <a
 * href="https://github.com/ethereum/wiki/wiki/RLP">here</a>.
 */
public class RlpDecoder {
	/**
	 * [0x80] If a string is 0-55 bytes long, the RLP encoding consists of a
	 * single byte with value 0x80 plus the length of the string followed by the
	 * string. The range of the first byte is thus [0x80, 0xb7].
	 */
	public static final short OFFSET_SHORT_STRING = 0x80;

	/**
	 * [0xb7] If a string is more than 55 bytes long, the RLP encoding consists
	 * of a single byte with value 0xb7 plus the length of the length of the
	 * string in binary form, followed by the length of the string, followed by
	 * the string. For example, a length-1024 string would be encoded as
	 * \xb9\x04\x00 followed by the string. The range of the first byte is thus
	 * [0xb8, 0xbf].
	 */
	public static final short OFFSET_LONG_STRING = 0xb7;

	/**
	 * [0xc0] If the total payload of a list (i.e. the combined length of all
	 * its items) is 0-55 bytes long, the RLP encoding consists of a single byte
	 * with value 0xc0 plus the length of the list followed by the concatenation
	 * of the RLP encodings of the items. The range of the first byte is thus
	 * [0xc0, 0xf7].
	 */
	public static int OFFSET_SHORT_LIST = 0xc0;

	/**
	 * [0xf7] If the total payload of a list is more than 55 bytes long, the RLP
	 * encoding consists of a single byte with value 0xf7 plus the length of the
	 * length of the list in binary form, followed by the length of the list,
	 * followed by the concatenation of the RLP encodings of the items. The
	 * range of the first byte is thus [0xf8, 0xff].
	 */
	public static int OFFSET_LONG_LIST = 0xf7;

	public static final short RLP_EXCEPTION = 6;

	public static short decodeRlpList(byte[] data, short offset,
			byte[] destBuf, short destOffset, short[] lengthDest,
			short lengthDestOffset) {
		short prefix = (short) (data[offset] & 0xff);
		if (prefix >= OFFSET_SHORT_LIST && prefix <= OFFSET_LONG_LIST) {

			// 4. the data is a list if the range of the
			// first byte is [0xc0, 0xf7], and the concatenation of
			// the RLP encodings of all items of the list which the
			// total payload is equal to the first byte minus 0xc0 follows
			// the first byte;

			byte listLen = (byte) (prefix - OFFSET_SHORT_LIST);
			decodeArgumentLength(data, (short) (offset + 1), (short) (offset
					+ listLen + 1), destBuf, destOffset, lengthDest,
					lengthDestOffset);
			return (short) (listLen + 1);
		} else if (prefix > OFFSET_LONG_LIST) {
			byte lenOfListLen = (byte) (prefix - OFFSET_LONG_LIST);
			short listLen = calcLength(lenOfListLen, data, offset);
			decodeArgumentLength(data, (short) (offset + lenOfListLen + 1),
					(short) (offset + lenOfListLen + listLen + 1), destBuf,
					destOffset, lengthDest, lengthDestOffset);
			return (short) (listLen + lenOfListLen + 1);
		}
		CryptoException.throwIt(RLP_EXCEPTION);

		return 0;
	}

	private static void decodeArgumentLength(byte[] data, short offset,
			short length, byte[] destBuf, short destOffset, short[] lengthDest,
			short lengthDestOffset) {
		short start = offset;
		short lengthPivot = lengthDestOffset;
		short offsetPivot = destOffset;
		short end = (short) (length - offset);
		if (length == 0) {
			return;
		}

		// end is derived from input data during recursion, so we must validate
		// it
		if (end < 0 || end > data.length) {
			CryptoException.throwIt(RLP_EXCEPTION);
		}

		while (start < end) {
			short prefix = (short) (data[start] & 0xff);
			if (prefix < OFFSET_SHORT_STRING) {

				// 1. the data is a string if the range of the
				// first byte(i.e. prefix) is [0x00, 0x7f],
				// and the string is the first byte itself exactly;
				destBuf[offsetPivot++] = (byte) (prefix);
				lengthDest[lengthPivot] = 1;
				lengthPivot += 1;
				start += 1;
			} else if (prefix == OFFSET_SHORT_STRING) {
				// null
				start += 1;
				lengthDest[lengthPivot] = 0;
				lengthPivot += 1;
			} else if (prefix <= OFFSET_LONG_STRING) {

				// 2. the data is a string if the range of the
				// first byte is [0x80, 0xb7], and the string
				// which length is equal to the first byte minus 0x80
				// follows the first byte;

				byte strLen = (byte) (prefix - OFFSET_SHORT_STRING);

				// Input validation
				if (strLen > end - (offset + 1)) {
					CryptoException.throwIt(RLP_EXCEPTION);
				}
				start += 1;
				Util.arrayCopyNonAtomic(data, start, destBuf, offsetPivot,
						strLen);
				lengthDest[lengthPivot] = strLen;
				lengthPivot += 1;
				offsetPivot += strLen;
				start += strLen;
			} else if (prefix < OFFSET_SHORT_LIST) {

				// 3. the data is a string if the range of the
				// first byte is [0xb8, 0xbf], and the length of the
				// string which length in bytes is equal to the
				// first byte minus 0xb7 follows the first byte,
				// and the string follows the length of the string;

				byte lenOfStrLen = (byte) (prefix - OFFSET_LONG_STRING);
				int strLen = calcLength(lenOfStrLen, data, start);

				// Input validation
				if (strLen > end - (start + lenOfStrLen + 1)) {
					CryptoException.throwIt(RLP_EXCEPTION);
				}
				start += lenOfStrLen + 1;
				Util.arrayCopyNonAtomic(data, start, destBuf, offsetPivot,
						(short) strLen);
				lengthDest[lengthPivot] = (short) strLen;
				lengthPivot += 1;
				offsetPivot += strLen;
				start += strLen;
			} else if (prefix <= OFFSET_LONG_LIST) {

				// 4. the data is a list if the range of the
				// first byte is [0xc0, 0xf7], and the concatenation of
				// the RLP encodings of all items of the list which the
				// total payload is equal to the first byte minus 0xc0 follows
				// the first byte;

				byte listLen = (byte) (prefix - OFFSET_SHORT_LIST);
				decodeArgumentLength(data, (short) (start + 1), (short) (start
						+ listLen + 1), destBuf, offsetPivot, lengthDest,
						lengthPivot);
				return;
			} else {
				byte lenOfListLen = (byte) (prefix - OFFSET_LONG_LIST);
				short listLen = calcLength(lenOfListLen, data, start);
				decodeArgumentLength(data, (short) (start + lenOfListLen + 1),
						(short) (start + lenOfListLen + listLen + 1), destBuf,
						offsetPivot, lengthDest, lengthPivot);
				return;
			}
		}
	}

	private static short calcLength(byte lengthOfLength, byte[] data, short pos) {
		byte pow = (byte) (lengthOfLength - 1);
		short length = 0;
		for (short i = 1; i <= lengthOfLength; ++i) {
			length += ((data[(short) (pos + i)] & 0xff)) << (8 * pow);
			pow--;
		}
		if (length < 0) {
			CryptoException.throwIt(RLP_EXCEPTION);
		}
		return length;
	}
}
