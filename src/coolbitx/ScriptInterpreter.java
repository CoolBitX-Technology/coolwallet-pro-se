package coolbitx;

import javacard.framework.Util;
import javacard.framework.ISOException;

public class ScriptInterpreter {

	public static final byte scriptVersion = 7;

	public static byte[] script; // special
	public static byte[] argument; // in
	public static byte[] cache1; // in/out
	public static byte[] cache2; // in/out
	public static byte[] transaction; // in/out
	public static byte[] detail; // special
	public static short[] array; // store array start offset
	public static short[] count; // store object number in array
	public static byte[] rlpArgs; // store rlp argument
	public static short[] rlpArgsLengths; // store rlp arguments length
	public static byte[] coinType; // special
	private static final short scriptMax = 3000;
	private static final short argumentMax = 10240;
	private static final short cache1Max = 300;
	private static final short cache2Max = 300;
	private static final short transactionMax = 9216;
	private static final short detailMax = 200;
	private static final short arrayMax = 16;
	private static final short rlpMax = 1024;
	private static final short rlpLengthMax = 64;
	private static final short coinTypeMax = 4;
	private static short scriptLength;
	private static short argumentLength;
	private static int placeholderLength;
	private static short placeholderOffset;
	// private static short transactionLength;
	// private static short detailLength;
	private static short si, c1i, c2i, ti, di, ai; // , ci;
	private static boolean isCoinTypeExist = false;
	private static short bufferInt;
	private static short intCache, maxCache;

	private static boolean isExecuted = false;
	private static byte hashType, signType, remainDataType, argType;
	private static boolean isUTXOtx = false;

	private static final byte type_asc = (byte) 0x00;
	private static final byte type_bcd = (byte) 0x01;
	private static final byte type_addr = (byte) 0x02;
	private static final byte type_wrap = (byte) 0x03;
	private static byte detailIcon = (byte) 0xFF;

	public static void init() {
		script = new byte[scriptMax];
		argument = new byte[argumentMax];
		cache1 = new byte[cache1Max];
		cache2 = new byte[cache2Max];
		transaction = new byte[transactionMax];
		detail = new byte[detailMax];
		array = new short[arrayMax];
		count = new short[arrayMax];
		rlpArgs = new byte[rlpMax];
		rlpArgsLengths = new short[rlpLengthMax];
		coinType = new byte[coinTypeMax];
		CardInfo.set(CardInfo.SIGN_AESKEY_VALID, false);
		reset();
	}

	public static void uninit() {
		script = null;
		argument = null;
		cache1 = null;
		cache2 = null;
		transaction = null;
		detail = null;
		array = null;
		count = null;
		rlpArgs = null;
		rlpArgsLengths = null;
		coinType = null;
	}

	public static void reset() {
		Util.arrayFillNonAtomic(cache1, (short) 0, cache1Max, (byte) 0);
		Util.arrayFillNonAtomic(cache2, (short) 0, cache2Max, (byte) 0);
		Util.arrayFillNonAtomic(transaction, (short) 0, transactionMax,
				(byte) 0);
		Util.arrayFillNonAtomic(detail, (short) 0, detailMax, (byte) 0);
		Common.clearArray(array);
		Common.clearArray(count);
		Util.arrayFillNonAtomic(coinType, (short) 0, coinTypeMax, (byte) 0);
		si = c1i = c2i = ti = di = ai = 0;
		placeholderOffset = 0;
		placeholderLength = 0;
		isCoinTypeExist = false;
		bufferInt = 0;
		intCache = maxCache = 0;
		isExecuted = false;
		hashType = signType = remainDataType = argType = 0;
		detailIcon = (byte) 0xFF;
		isUTXOtx = false;
	}

	public static void setScript(byte[] buf, short offset, short length) {
		length -= 72;
		if (!SignUtil.isVerifiedFixedLength(buf, offset, length, buf,
				(short) (offset + length),
				KeyUtil.getPubKey(KeyStore.ScriptPubKey, Common.OFFSET_ZERO))) {
			ISOException.throwIt((short) 0x6ACC);
		}
		Util.arrayFillNonAtomic(script, (short) 0, scriptMax, (byte) 0);
		Util.arrayCopyNonAtomic(buf, offset, script, (short) 0, length);
		scriptLength = length;
	}

	public static short setArgument(byte[] buf, short offset, short length,
			byte sequence, byte total) {
		if (sequence == 0) {
			argumentLength = 0;
		}
		argumentLength = Util.arrayCopyNonAtomic(buf, offset, argument,
				argumentLength, length);
		if ((total == 0) || ((sequence + 1) == total)) {
			return argumentLength;
		}
		return 0;
	}

	public static short getTransaction(byte[] destBuf, short destOffset) {
		// short ret = ti > 250 ? 250 : ti;
		short ret = ti;
		Util.arrayCopyNonAtomic(transaction, (short) 0, destBuf, destOffset,
				ret);
		return ret;
	}

	public static short getTxDetail(byte[] destBuf, short destOffset) {
		short ret = di;
		if (Main.developMode) {
			destBuf[destOffset++] = (byte) (4 + 2);
			destBuf[destOffset++] = detailIcon;
			destBuf[destOffset++] = type_asc;
			destBuf[destOffset++] = 'T';
			destBuf[destOffset++] = 'E';
			destBuf[destOffset++] = 'S';
			destBuf[destOffset++] = 'T';
			ret += 7;
		}
		Util.arrayCopyNonAtomic(detail, (short) 0, destBuf, destOffset, di);
		return ret;
	}

	public static void execute() {
		reset();
		short headerLength = script[si++];
		if (headerLength < 3) {
			ISOException.throwIt((short) 0x6ACA);
		}
		byte version = script[si++];
		if (version > scriptVersion) {
			ISOException.throwIt((short) 0x6A02);
		}
		hashType = script[si++];
		signType = script[si++];
		if (headerLength >= 4) {
			remainDataType = script[si++];
		}
		if (headerLength >= 5) {
			argType = script[si++];
		}
		if (argType == 0x1) { // rlp arg type
			short rlpLength = RlpDecoder.decodeRlpList(argument, (short) 0,
					rlpArgs, (short) 0, rlpArgsLengths, (short) 0);
			if (rlpLength != 0) {
				short remaining = (short) (argumentLength - rlpLength);
				// Struct the data length and offset for argument
				Util.arrayCopyNonAtomic(argument, rlpLength, argument,
						(short) 0, remaining);
				Util.arrayFillNonAtomic(argument, remaining, argumentLength,
						(byte) 0x00);
			}
		}
		for (; si < scriptLength;) {
			byte command = script[si++];
			byte[] dataBuf = getDataBuffer((byte) ((script[si] >> 4) & 0x0F));
			short dataOffset = 0;
			short dataLength = 0;
			if (dataBuf != null) {
				dataOffset = (short) (script[si] & 0x0F);
				si++;
				dataLength = (short) ((script[si] >> 4) & 0x0F);
			}
			byte[] destBuf = getDestBuffer((byte) (script[si] & 0x0F));
			short destOffset = getDestOffset(destBuf);
			si++;
			short argInt0 = (short) ((script[si] >> 4) & 0x0F);
			short argInt1 = (short) (script[si] & 0x0F);
			si++;
			// If dataLength equals to 0xA means it is a rlp argument.
			if (dataLength == (byte) 0xA) {
				short rlpOffset = getInt((byte) dataOffset);
				dataOffset = 0;
				for (short i = 0; i < rlpOffset; i++) {
					dataOffset += rlpArgsLengths[i];
				}
				dataLength = rlpArgsLengths[rlpOffset];
			} else {
				dataOffset = getInt((byte) dataOffset);
				dataLength = getInt((byte) dataLength);
			}
			argInt0 = getInt((byte) argInt0);
			argInt1 = getInt((byte) argInt1);
			// short destLength = 0;
			if (dataLength < 0) {
				dataLength *= -1;
				while (dataBuf[dataOffset] == 0 && dataLength > 0) {
					dataOffset++;
					dataLength--;
				}
			}
			short destLength;

			switch (command) {
			case (byte) 0xC7:
				Util.arrayCopyNonAtomic(script, si, coinType, (short) 0,
						(short) 4);
				si += 4;
				isCoinTypeExist = true;
				break;
			case (byte) 0xCC:
				// Constant copy
				// from script to dest-stream
				Util.arrayCopyNonAtomic(script, si, destBuf, destOffset,
						argInt0);
				si += argInt0;
				addDestOffset(destBuf, argInt0);
				break;
			case (byte) 0xCA:
				// Constant copy
				// from array-buffer to dest-stream
				Util.arrayCopyNonAtomic(dataBuf, dataOffset, destBuf,
						destOffset, dataLength);
				addDestOffset(destBuf, dataLength);
				break;
			case (byte) 0xC1: {
				// Constant copy switch
				// from script to dest-stream
				// (data,offset,caseNumber,dest)
				byte index = dataBuf[dataOffset];
				if (index < 0 || index >= argInt0) {
					ISOException.throwIt((short) 0x6A0D);
				}
				for (short i = 0; i < argInt0; i++) {
					dataLength = (short) (script[si++] & 0x00FF);
					if (i == index) {
						Util.arrayCopyNonAtomic(script, si, destBuf,
								destOffset, dataLength);
						addDestOffset(destBuf, dataLength);
					}
					si += dataLength;
				}
				break;
			}
			// case (byte) 0xC8:
			// Put length
			// (referenceData,dest,addValue)
			// si++;
			// getDataBuffer(p0);
			// destBuf = getDestBuffer(p1);
			// length = (short) (maxCache + (script[si++] & 0x00FF));
			// Util.setShort(destBuf, destOffset, length);
			// addDestOffset(destBuf, (short) 2);
			// break;
			case (byte) 0xC2:
				// copy RLP string
				if (dataLength == 1 && (dataBuf[dataOffset] & 0x00FF) < 0x80) {
					;
				} else if (dataLength <= 55) {
					destBuf[destOffset] = (byte) (dataLength + 0x80);
					addDestOffset(destBuf, (short) 1);
				} else if (dataLength <= 255) {
					destBuf[destOffset] = (byte) (0xB8);
					destBuf[(short) (destOffset + 1)] = (byte) (dataLength);
					addDestOffset(destBuf, (short) 2);
				} else {
					destBuf[destOffset] = (byte) (0xB9);
					destBuf[(short) (destOffset + 1)] = (byte) (dataLength / 256);
					destBuf[(short) (destOffset + 2)] = (byte) (dataLength % 256);
					addDestOffset(destBuf, (short) 3);
				}
				Util.arrayCopyNonAtomic(dataBuf, dataOffset, destBuf,
						getDestOffset(destBuf), dataLength);
				addDestOffset(destBuf, dataLength);
				break;
			case (byte) 0xC3:
				// set RLP list
				dataLength -= argInt0;
				if (dataLength <= 55) {
					Util.arrayCopyNonAtomic(dataBuf, (short) argInt0, destBuf,
							(short) 1, dataLength);
					destBuf[0] = (byte) (0x00C0 + dataLength);
					argInt1 = (short) (1 + dataLength);
				} else if (dataLength <= 255) {
					Util.arrayCopyNonAtomic(transaction, (short) argInt0,
							transaction, (short) 2, dataLength);
					destBuf[0] = (byte) 0xF8;
					destBuf[1] = (byte) dataLength;
					argInt1 = (short) (2 + dataLength);
				} else {
					Util.arrayCopyNonAtomic(transaction, (short) argInt0,
							destBuf, (short) 3, dataLength);
					destBuf[0] = (byte) 0xF9;
					destBuf[1] = (byte) (dataLength / 256);
					destBuf[2] = (byte) (dataLength % 256);
					argInt1 = (short) (3 + dataLength);
				}
				if (destBuf == cache1) {
					c1i = argInt1;
				}
				if (destBuf == cache2) {
					c2i = argInt1;
				}
				if (destBuf == transaction) {
					ti = argInt1;
				}
				break;
			case (byte) 0xBA:
			// baseConvert
			// from array-buffer to dest-stream
			// (data,offset,length,dest,destLength,destCharset,argument)
			{
				destLength = argInt0;
				byte[] destCharset = getCharset((byte) argInt1);
				short inArg = getBaseConvertInnerArgument(script[si++]);
				destLength = NumberUtil
						.baseConvert(
								dataBuf,
								dataOffset,
								dataLength,
								NumberUtil.binaryCharset,
								(short) 0,
								(short) 256,
								destBuf,
								destOffset,
								destLength,
								destCharset,
								(short) 0,
								(short) (destCharset == cache1 ? c1i
										: (destCharset == NumberUtil.binaryCharset ? 256
												: destCharset.length)),
								(short) (inArg | NumberUtil.outBuffered));
				addDestOffset(destBuf, destLength);
			}
				break;
			case (byte) 0xB5:
				// set bufferInt to data[]
				if (dataLength == 1) {
					bufferInt = dataBuf[dataOffset];
				} else if (dataLength == 2) {
					bufferInt = Util.getShort(dataBuf, dataOffset);
				} else {
					ISOException.throwIt((short) 0x6A76);
				}
				break;
			case (byte) 0xB1:
				// set bufferInt to dataLength
				bufferInt = dataLength;
				break;
			case (byte) 0xC6:
				// put padding zeroes according to bufferInt
				if (bufferInt % argInt0 != 0) {
					argInt1 = (short) (argInt0 - (bufferInt % argInt0));
					Util.arrayFillNonAtomic(destBuf, destOffset, argInt1,
							(byte) 0);
					addDestOffset(destBuf, argInt1);
				}
				break;
			case (byte) 0xB9:
				// put bufferInt to dest in 2Bytes
				destBuf[destOffset] = (byte) (bufferInt / 256);
				destBuf[(short) (destOffset + 1)] = (byte) (bufferInt % 256);
				addDestOffset(destBuf, (short) 2);
				break;
			case (byte) 0x5A:
				// hash
				// (data,offset,length,dest,-,hashType)
				getHash(dataBuf, dataOffset, dataLength, destBuf, destOffset,
						(byte) (argInt0 | (argInt1 << 4)));
				break;
			case (byte) 0x6C:
			// derive ECDSA publicKey with
			{
				// final short workLength = (short) 65;
				// byte[] temp = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
				// short tempOffset = WorkCenter.getWorkspaceOffset(workLength);
				// Bip32.getDerivedPublicKey(dataBuf, dataOffset, dataLength,
				// (byte) 1, temp, tempOffset);
				// Util.arrayCopyNonAtomic(temp, tempOffset, destBuf,
				// destOffset,
				// (short) 33);
				// WorkCenter.release(WorkCenter.WORK1, workLength);
				short len = KeyManager.getDerivedPublicKey(dataBuf, dataOffset,
						dataLength, false, destBuf, destOffset);
				addDestOffset(destBuf, len);
			}
				break;
			case (byte) 0x15:
				// skip incoming script
				// (fullJumpDistance)
				si += argInt0;
				break;
			case (byte) 0x1A:
				// skip incoming script unless data[]==script[si]
				// (data,offset,length,jumpDistance)
				if (Util.arrayCompare(dataBuf, dataOffset, script, si,
						dataLength) != 0) {
					si += argInt0;
				}
				si += dataLength;
				break;
			case (byte) 0x12:
				// skip incoming script
				// unless script[si] <= data[] <= script[si+]
				// (data,offset,length,jumpDistance)
				if (Util.arrayCompare(script, si, dataBuf, dataOffset,
						dataLength) == 1
						|| Util.arrayCompare(dataBuf, dataOffset, script,
								(short) (si + dataLength), dataLength) == 1) {
					si += argInt0;
				}
				si += dataLength * 2;
				break;
			case (byte) 0x11:
				// skip incoming script unless data[] is signed by sign[]
				// (data,offset,length,signBuf=argument,offset,jumpDistance)
				if (!SignUtil.isVerifiedFixedLength(dataBuf, dataOffset,
						dataLength, argument, argInt1, KeyUtil.getPubKey(
								KeyStore.CBPubKey, Common.OFFSET_ZERO))) {
					si += argInt0;
				}
				break;
			case (byte) 0x25:
				// reset destBuf (dest,newOffset)
				if (destBuf == cache1) {
					c1i = argInt0;
				}
				if (destBuf == cache2) {
					c2i = argInt0;
				}
				if (destBuf == transaction) {
					ti = argInt0;
				}
				break;
			case (byte) 0x29:
				// check regular string
				for (short i = 0; i < dataLength; i++) {
					short c = dataBuf[(short) (dataOffset + i)];
					if (c < 0x20 || c > 0x7E || c == '\"') {
						ISOException.throwIt((short) 0x6A74);
					}
				}
				break;
			case (byte) 0xD1:
				detailIcon = (byte) argInt0;
				break;
			case (byte) 0xD2:
				// add wrapPage from script to detail (constLength,constLength)
				Check.checkRange((short) 0, argInt0, (short) 8);
				Check.checkRange((short) 0, argInt1, (short) 7);
				detail[(short) (di++)] = 17;
				detail[(short) (di++)] = detailIcon;
				detail[(short) (di++)] = type_wrap;
				Util.arrayFillNonAtomic(detail, di, (short) 15, (byte) ' ');

				Util.arrayCopyNonAtomic(script, si, detail,
						(short) (di + 8 - argInt0), argInt0);
				si += argInt0;

				Util.arrayCopyNonAtomic(script, si, detail,
						(short) (di + 15 - argInt1), (short) argInt1);
				si += argInt1;
				di += 15;
				break;
			case (byte) 0xDC:
				// add messagePage from script to detail (constLength)
				detail[(short) (di++)] = (byte) (argInt0 + 2);
				detail[(short) (di++)] = detailIcon;
				detail[(short) (di++)] = type_asc;
				Util.arrayCopyNonAtomic(script, si, detail, di, argInt0);
				si += argInt0;
				di += argInt0;
				break;
			case (byte) 0xDE:
				// add messagePage from inBuf to detail
				detail[(short) (di++)] = (byte) (dataLength + 2);
				detail[(short) (di++)] = detailIcon;
				detail[(short) (di++)] = type_asc;
				Util.arrayCopyNonAtomic(dataBuf, dataOffset, detail, di,
						dataLength);
				di += dataLength;
				break;
			case (byte) 0xDD:
				// add addressPage from array-buffer to detail
				if (CardInfo.getDisplayType() != 0) {
					break;
				}
				detail[(short) (di++)] = (byte) (dataLength + 2);
				detail[(short) (di++)] = detailIcon;
				detail[(short) (di++)] = type_addr;
				Util.arrayCopyNonAtomic(dataBuf, dataOffset, detail, di,
						dataLength);
				di += dataLength;
				break;
			case (byte) 0xDA:
			// add amoungPage from array-buffer to detail
			{
				detail[(short) (di++)] = (byte) 10;// 1+1+8
				detail[(short) (di++)] = detailIcon;
				detail[(short) (di++)] = type_bcd;
				Util.arrayFillNonAtomic(detail, di, (short) 8, (byte) 0);
				final short decimalLength = (short) ((argInt0 + 1) / 2);
				// 4 equals to integer part CoolWallet should display.
				final short integerLength = 4;
				final short extraSpace = 20;
				final short amountLength = (short) (decimalLength
						+ integerLength + extraSpace);

				byte[] temp = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
				short tempOffset = WorkCenter.getWorkspaceOffset(amountLength);
				NumberUtil.baseConvert(dataBuf, dataOffset, dataLength,
						NumberUtil.binaryCharset, temp, tempOffset,
						amountLength, NumberUtil.bcdCharset);

				if (argInt0 % 2 != 0) {
					if ((temp[tempOffset] & 0x00F0) != 0) {
						ISOException.throwIt((short) 0x6A71);
					}
					MathUtil.shiftLeftFixed(temp, tempOffset, amountLength,
							temp, tempOffset, (byte) 4);
				}

				short limitLength = (short) (integerLength + decimalLength);
				short showLength = limitLength >= 8 ? 8 : limitLength;
				for (short i = amountLength; i > limitLength; i--)
					if (temp[(short) (tempOffset + amountLength - i)] != 0) {
						ISOException.throwIt((short) 0x6A72);
					}
				Util.arrayCopyNonAtomic(temp, (short) (tempOffset
						+ amountLength - limitLength), detail, di, showLength);
				di += 8;

				WorkCenter.release(WorkCenter.WORK, amountLength);
			}
				break;
			case (byte) 0xFF:
				ISOException.throwIt((short) 0x6AE2);
				break;
			// ================ script verion 1 ================
			case (byte) 0xA1:
				destLength = NumberUtil.varint(dataBuf, (short) dataOffset,
						(short) dataLength, destBuf, (short) destOffset);
				addDestOffset(destBuf, destLength);
				break;
			case (byte) 0xBF:
				// Protocol Buffers
				// https://developers.google.com/protocol-buffers/docs/encoding
				byte wireType = (byte) argInt0;
				if (wireType == 0) { // Varint
					destLength = NumberUtil.varint(dataBuf, dataOffset,
							dataLength, destBuf, destOffset);
					addDestOffset(destBuf, destLength);
				} else if (wireType == 2) { // Length-delimited
					byte[] lengthBuf = WorkCenter
							.getWorkspaceArray(WorkCenter.WORK);
					short lengthOffset = WorkCenter
							.getWorkspaceOffset((short) 2);
					Util.setShort(lengthBuf, lengthOffset, dataLength);
					destLength = NumberUtil.varint(lengthBuf, lengthOffset,
							(short) 2, destBuf, destOffset);
					Util.arrayCopyNonAtomic(dataBuf, dataOffset, destBuf,
							(short) (destOffset + destLength), dataLength);
					addDestOffset(destBuf, (short) (destLength + dataLength));
					WorkCenter.release(WorkCenter.WORK, (short) 2);
				} else {
					ISOException.throwIt((short) 0x6A73);
				}
				break;
			case (byte) 0xA0: {
				// Record array length offset for unknown data length
				// like RLP, protocol buffer...
				array[ai] = ti;
				if (ai > 0) {
					count[(short) (ai - 1)]++;
				}
				ai++;
				if (ai > arrayMax) {
					ISOException.throwIt((short) 0x6205);
				}
				break;
			}
			case (byte) 0xBE: {
				if (ai <= 0) {
					ISOException.throwIt((short) 0x6A75);
				}
				short arrayOffset = array[--ai];
				short arrayLen = (short) (ti - arrayOffset);
				if (arrayLen < 0) {
					ISOException.throwIt((short) 0x6A76);
				}

				if (argInt0 == 0) { // protocol buffer array end
					Util.setShort(cache2, c2i, arrayLen);
					short varLen = NumberUtil.varint(cache2, c2i, (short) 2,
							cache2, (short) (c2i + 2));
					if (varLen != 0) {
						Util.arrayCopyNonAtomic(transaction, arrayOffset,
								transaction, (short) (arrayOffset + varLen),
								arrayLen);
						Util.arrayCopyNonAtomic(cache2, (short) (c2i + 2),
								transaction, arrayOffset, varLen);
						ti += varLen;
					}
				} else if (argInt0 == 1) { // rlp array end
					// Apply placeholderLength to arrayLen to make rlp encoded
					// correct.
					int rlpLength = (int) arrayLen;
					if (placeholderLength != 0)
						rlpLength += placeholderLength;
					if (rlpLength <= 55) {
						Util.arrayCopyNonAtomic(transaction, arrayOffset,
								transaction, (short) (arrayOffset + 1),
								arrayLen);
						destBuf[arrayOffset] = (byte) (0x00C0 + rlpLength);
						ti += 1;
						placeholderOffset += 1;
					} else if (rlpLength <= 255) {
						Util.arrayCopyNonAtomic(transaction, arrayOffset,
								transaction, (short) (arrayOffset + 2),
								arrayLen);
						destBuf[arrayOffset] = (byte) 0xF8;
						destBuf[(short) (arrayOffset + 1)] = (byte) rlpLength;
						ti += 2;
						placeholderOffset += 2;
					} else {
						Util.arrayCopyNonAtomic(transaction, arrayOffset,
								transaction, (short) (arrayOffset + 3),
								arrayLen);
						destBuf[arrayOffset] = (byte) 0xF9;
						destBuf[(short) (arrayOffset + 1)] = (byte) (rlpLength / 256);
						destBuf[(short) (arrayOffset + 2)] = (byte) (rlpLength % 256);
						ti += 3;
						placeholderOffset += 3;
					}
				} else if (argInt0 == 2) { // message pack map end
					// Take key and value as a pair
					short countNumber = (short) (count[ai] / 2);
					count[ai] = 0;
					// temporary move data 5 bytes down to prevent overwritten
					// by message pack header
					Util.arrayCopyNonAtomic(transaction, arrayOffset,
							transaction, (short) (arrayOffset + 5), arrayLen);
					destLength = NumberUtil.messagePack(transaction,
							(short) (arrayOffset + 5), countNumber,
							NumberUtil.typeMap, transaction, arrayOffset);
					Util.arrayCopyNonAtomic(transaction,
							(short) (arrayOffset + 5), transaction,
							(short) (arrayOffset + destLength), arrayLen);
					addDestOffset(destBuf, destLength);
				} else if (argInt0 == 3) { // message pack array end
					// Take key and value as a pair
					short countNumber = count[ai];
					count[ai] = 0;
					// temporary move data 5 bytes down to prevent overwritten
					// by message pack header
					Util.arrayCopyNonAtomic(transaction, arrayOffset,
							transaction, (short) (arrayOffset + 5), arrayLen);
					destLength = NumberUtil.messagePack(transaction,
							(short) (arrayOffset + 5), countNumber,
							NumberUtil.typeArray, transaction, arrayOffset);
					Util.arrayCopyNonAtomic(transaction,
							(short) (arrayOffset + 5), transaction,
							(short) (arrayOffset + destLength), arrayLen);
					addDestOffset(destBuf, destLength);
				}
				break;
			}
			// ================ script version 2 ================
			case (byte) 0xA2:
				destLength = NumberUtil.scaleEncode(dataBuf, dataOffset,
						dataLength, destBuf, destOffset);
				addDestOffset(destBuf, destLength);
				break;
			case (byte) 0xA3:
				destLength = NumberUtil.scaleDecode(dataBuf, dataOffset,
						destBuf, destOffset);
				addDestOffset(destBuf, destLength);
				break;
			// ================ script version 5 ================
			case (byte) 0xC4: {
				placeholderOffset = destOffset;
				if (dataLength != 4) {
					ISOException.throwIt((short) 0x6700);
				}
				placeholderLength = NumberUtil.byteArrayToInt(dataBuf,
						dataOffset, dataLength);
				// RLP
				if (argInt0 == 0) {
					if (placeholderLength <= 55) {
						destBuf[destOffset] = (byte) (placeholderLength + 0x80);
						placeholderOffset += 1;
						addDestOffset(destBuf, (short) 1);
					} else if (placeholderLength <= 255) {
						destBuf[destOffset] = (byte) (0xB8);
						destBuf[(short) (destOffset + 1)] = (byte) (placeholderLength);
						placeholderOffset += 2;
						addDestOffset(destBuf, (short) 2);
					} else {
						destBuf[destOffset] = (byte) (0xB9);
						destBuf[(short) (destOffset + 1)] = (byte) (placeholderLength / 256);
						destBuf[(short) (destOffset + 2)] = (byte) (placeholderLength % 256);
						placeholderOffset += 3;
						addDestOffset(destBuf, (short) 3);
					}
				} else if (argInt0 == 1) { // Protobuf bytes
					byte[] lengthBuf = WorkCenter
							.getWorkspaceArray(WorkCenter.WORK);
					short lengthOffset = WorkCenter
							.getWorkspaceOffset(dataLength);
					destLength = NumberUtil.varint(dataBuf, dataOffset,
							dataLength, lengthBuf, lengthOffset);
					Util.arrayCopyNonAtomic(lengthBuf, lengthOffset, destBuf,
							destOffset, destLength);
					placeholderOffset += destLength;
					addDestOffset(destBuf, destLength);
					WorkCenter.release(WorkCenter.WORK, dataLength);
				} else if (argInt0 == 2) { // utxo
					isUTXOtx = true;
				} else if (argInt0 == 3) {
					// do nothing, only for test
				}
				break;
			}
			// ================ script version 6 ================
			case (byte) 0xC5: {
				// message pack
				byte type = (byte) argInt0;
				if (type < 0 || type > 3) {
					ISOException.throwIt((short) 0x6A0E);
				}
				destLength = NumberUtil.messagePack(dataBuf, dataOffset,
						dataLength, type, destBuf, destOffset);
				addDestOffset(destBuf, destLength);
				if (ai == 0) {
					ISOException.throwIt((short) 0x6A0F);
				}
				count[(short) (ai - 1)]++;
				break;
			}
			case (byte) 0xC8:
				// message pack string from script
				destLength = NumberUtil.messagePack(script, si, argInt0,
						NumberUtil.typeString, destBuf, destOffset);
				si += argInt0;
				addDestOffset(destBuf, destLength);
				if (ai == 0) {
					ISOException.throwIt((short) 0x6A0F);
				}
				count[(short) (ai - 1)]++;
				break;
			case (byte) 0x1C: {
				// Check whether data is empty
				if (dataLength != 0) {
					si += argInt0;
				}
				break;
			}
			case (byte) 0xae:
				// tagged hash, for now only use SHA-256
				switch (argInt0) {
				case 0:
					Bip340.taggedHash(Bip340.challenge, dataBuf, dataOffset,
							dataLength, destBuf, destOffset, ShaUtil.m_sha_256);
					break;
				case 1:
					Bip340.taggedHash(Bip340.aux, dataBuf, dataOffset,
							dataLength, destBuf, destOffset, ShaUtil.m_sha_256);
					break;
				case 2:
					Bip340.taggedHash(Bip340.nonce, dataBuf, dataOffset,
							dataLength, destBuf, destOffset, ShaUtil.m_sha_256);
					break;
				case 3:
					Bip340.taggedHash(Bip340.TapTweak, dataBuf, dataOffset,
							dataLength, destBuf, destOffset, ShaUtil.m_sha_256);
					break;
				case 4:
					Bip340.taggedHash(Bip340.TapSighash, dataBuf, dataOffset,
							dataLength, destBuf, destOffset, ShaUtil.m_sha_256);
					break;
				default:
					ISOException.throwIt((short) 0x6A01);
				}
				break;
			default:
				ISOException.throwIt((short) 0x6A01);
				break;
			}
		}
		Util.arrayFillNonAtomic(argument, (short) 0, argumentMax, (byte) 0);
		Common.clearArray(rlpArgs);
		Common.clearArray(rlpArgsLengths);
		argumentLength = 0;
		isExecuted = true;
	}

	public static boolean validateSignState(byte[] path, short pathOffset,
			short pathLength) {
		if (!isExecuted) {
			ISOException.throwIt((short) 0x6AC0);
		}
		if (signType == 0) {
			return false;
		}
		if (isCoinTypeExist) {
			if (pathLength < 9) {
				ISOException.throwIt((short) 0x6A0B);
			}
			if ((path[(short) (pathOffset + 5)] & 0x7F) != coinType[0]
					|| Util.arrayCompare(path, (short) (pathOffset + 6),
							coinType, (short) 1, (short) 3) != 0) {
				ISOException.throwIt((short) 0x6A0C);
			}
		}
		return true;
	}

	public static short signTransaction(byte[] path, short pathOffset,
			short pathLength, byte[] destBuf, short destOffset) {
		short ret = 0;
		if (isUTXOtx) {
			return ret;
		}
		if (!validateSignState(path, pathOffset, pathLength))
			return ret;
		// If hashType is zero means transaction does not need to hash.
		if (hashType != 0) {
			short workLength = Common.LENGTH_SHA256;
			byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
			short workspaceOffset = WorkCenter.getWorkspaceOffset(workLength);

			getHash(transaction, (short) 0, ti, workspace, workspaceOffset,
					hashType);
			ret = KeyManager.signByDerivedKey(workspace, workspaceOffset,
					workLength, path, pathOffset, pathLength, signType,
					destBuf, destOffset);
			WorkCenter.release(WorkCenter.WORK1, workLength);
		} else {
			ret = KeyManager.signByDerivedKey(transaction, (short) 0, ti, path,
					pathOffset, pathLength, signType, destBuf, destOffset);
		}
		return ret;
	}

	public static short signSegmentData(byte[] data, short offset,
			short length, byte[] path, short pathOffset, short pathLength,
			byte[] destBuf, short destOffset, boolean shouldUpdateTransaction) {
		short ret = 0;
		if (!validateSignState(path, pathOffset, pathLength))
			return ret;
		if (shouldUpdateTransaction) {
			getUpdateHash(transaction, (short) 0, placeholderOffset, hashType);
		}
		// Hashing data
		getUpdateHash(data, offset, length, hashType);
		if (isUTXOtx) {
			placeholderLength = 0;
		} else {
			placeholderLength -= length;
		}
		if (placeholderLength != 0) {
			return ret;
		}
		short remainLength = (short) (ti - placeholderOffset);
		short workLength = Common.LENGTH_SHA256;
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short workspaceOffset = WorkCenter.getWorkspaceOffset(workLength);

		getHash(transaction, placeholderOffset, remainLength, workspace,
				workspaceOffset, hashType);

		ret = KeyManager.signByDerivedKey(workspace, workspaceOffset,
				workLength, path, pathOffset, pathLength, signType, destBuf,
				destOffset);
		WorkCenter.release(WorkCenter.WORK1, workLength);
		return ret;
	}

	private static final byte[] utxoConstant = { (byte) 0x01, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x81, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x41, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
	private static final byte[] utxoRBFConstant = { (byte) 0x02, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0xFD, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x81, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x41, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
	private static final byte[] scriptConstant = { (byte) 0x19, (byte) 0x76,
			(byte) 0xA9, (byte) 0x14, (byte) 0x88, (byte) 0xAC, (byte) 0x17,
			(byte) 0xA9, (byte) 0x14, (byte) 0x87, (byte) 0x3F, (byte) 0x76,
			(byte) 0xA9, (byte) 0x14, (byte) 0x88, (byte) 0xAC, (byte) 0x3D,
			(byte) 0xA9, (byte) 0x14, (byte) 0x87, (byte) 0x20, (byte) 0x03,
			(byte) 0xB4 };

	private static void updateBtcScript(byte[] utxoArgument,
			short utxoArgumentOffset, byte type) {
		short headOffset = 0;
		short headLength = 0;
		short endOffset = 0;
		short endLength = 0;
		switch (utxoArgument[(short) (utxoArgumentOffset + 36)]) {
		case 0:
			headOffset = 0;
			headLength = 4;
			endOffset = 4;
			endLength = 2;
			break;
		case 1:
			headOffset = 6;
			headLength = 3;
			endOffset = 9;
			endLength = 1;
			break;
		default:
			ISOException.throwIt((short) 0x6AC5);
		}
		if (type == 0x13) {
			headOffset += 10;
			endOffset += 10;
		}
		ShaUtil.m_sha_256.update(scriptConstant, headOffset, headLength);
		ShaUtil.m_sha_256.update(utxoArgument,
				(short) (utxoArgumentOffset + 45), (short) 20);
		ShaUtil.m_sha_256.update(scriptConstant, endOffset, endLength);

		if (type == 0x13) {
			ShaUtil.m_sha_256.update(scriptConstant, (short) 20, (short) 1);
			ShaUtil.m_sha_256.update(utxoArgument,
					(short) (utxoArgumentOffset + 65), (short) 32);
			ShaUtil.m_sha_256.update(scriptConstant, (short) 21, (short) 1);
			ShaUtil.m_sha_256.update(utxoArgument,
					(short) (utxoArgumentOffset + 97), (short) 3);
			ShaUtil.m_sha_256.update(scriptConstant, (short) 22, (short) 1);
		}
	}

	public static short signUtxoTransaction(byte[] utxoArgument,
			short utxoArgumentOffset, byte[] path, short pathOffset,
			short pathLength, byte type, byte[] destBuf, short destOffset) {
		if (!isExecuted) {
			ISOException.throwIt((short) 0x6AC0);
		}
		if (isCoinTypeExist) {
			if (pathLength < 9) {
				ISOException.throwIt((short) 0x6A0B);
			}
			if ((path[(short) (pathOffset + 5)] & 0x7F) != coinType[0]
					|| Util.arrayCompare(path, (short) (pathOffset + 6),
							coinType, (short) 1, (short) 3) != 0) {
				ISOException.throwIt((short) 0x6A00);
			}
		}
		short workLength = 32;
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short workspaceOffset = WorkCenter.getWorkspaceOffset(workLength);
		short ret = 0;

		switch (type) {
		case 0x10: // legacyBTC
		case 0x13: // ZEN
		case 0x14: { // RBF legacyBTC
			if (remainDataType != 0x10) {
				ISOException.throwIt((short) 0x6AC2);
			}
			boolean isRBF = type == 0x14;

			byte[] utxo = isRBF ? utxoRBFConstant : utxoConstant;
			ShaUtil.m_sha_256.update(utxo, (short) 0, (short) 5);
			ShaUtil.m_sha_256.update(utxoArgument, utxoArgumentOffset,
					(short) 36);
			updateBtcScript(utxoArgument, utxoArgumentOffset, type);
			ShaUtil.m_sha_256.update(utxo, (short) 5, (short) 4);
			ShaUtil.m_sha_256.update(transaction, (short) 0, ti);
			ShaUtil.m_sha_256.doFinal(utxo, (short) 9, (short) 8, workspace,
					workspaceOffset);
			ShaUtil.SHA256(workspace, workspaceOffset, (short) 32, workspace,
					workspaceOffset);
			ret = KeyManager.signByDerivedKey(workspace, workspaceOffset,
					Common.LENGTH_SHA256, path, pathOffset, pathLength,
					KeyManager.SIGN_SECP256K1, destBuf, destOffset);
			break;
		}
		case 0x11: // segwitBTC
		case 0x12: // BCH
		case 0x15: { // RBF SegwitBTC
			if (remainDataType != 0x10) {
				ISOException.throwIt((short) 0x6AC2);
			}
			boolean isSegwit = type == 0x11 || type == 0x15;
			boolean isRBF = type == 0x15;

			byte[] utxo = isRBF ? utxoRBFConstant : utxoConstant;
			ShaUtil.S_DoubleSHA256(transaction, (short) 1, (short) (ti - 1),
					workspace, workspaceOffset);

			ShaUtil.m_sha_256.update(utxo, (short) 0, (short) 4);
			ShaUtil.m_sha_256.update(cache1, (short) 0, (short) 64);
			ShaUtil.m_sha_256.update(utxoArgument, utxoArgumentOffset,
					(short) 36);
			updateBtcScript(utxoArgument, utxoArgumentOffset, type);
			for (short i = 0; i < 8; i++) {
				ShaUtil.m_sha_256.update(utxoArgument,
						(short) (utxoArgumentOffset + 44 - i), (short) 1);
			}
			ShaUtil.m_sha_256.update(utxo, (short) 5, (short) 4);
			ShaUtil.m_sha_256.update(workspace, workspaceOffset, (short) 32);
			ShaUtil.m_sha_256.doFinal(utxo, (short) (isSegwit ? 14 : 19),
					(short) 8, workspace, workspaceOffset);
			ShaUtil.SHA256(workspace, workspaceOffset, (short) 32, workspace,
					workspaceOffset);
			ret = KeyManager.signByDerivedKey(workspace, workspaceOffset,
					Common.LENGTH_SHA256, path, pathOffset, pathLength,
					KeyManager.SIGN_SECP256K1, destBuf, destOffset);
			break;
		}
		case 0x26: // any data (for ERC20 approve to 0x)
			if (remainDataType != 0x20) {
				ISOException.throwIt((short) 0x6AC2);
			}
			ShaUtil.Keccak256(cache2, (short) 0, c2i, workspace,
					workspaceOffset);
			ret = KeyManager.signByDerivedKey(workspace, workspaceOffset,
					Common.LENGTH_SHA256, path, pathOffset, pathLength,
					KeyManager.SIGN_SECP256K1, destBuf, destOffset);
			break;
		default:
			ISOException.throwIt((short) 0x6AC7);
		}
		// Util.arrayCopyNonAtomic(transaction, (short) 0, destBuf, destOffset,
		// ti);ret = ti;
		WorkCenter.release(WorkCenter.WORK1, workLength);
		return ret;
	}

	private static byte[] getDataBuffer(byte command) {
		switch (command & 0x0F) {
		case 0:
			return null;
		case 0xA:
			maxCache = argumentLength;
			return argument;
		case 0xB:
			maxCache = rlpMax;
			return rlpArgs;
		case 0xE:
			maxCache = c1i;
			return cache1;
		case 0xF:
			maxCache = c2i;
			return cache2;
		case 0x7:
			maxCache = ti;
			return transaction;
		default:
			ISOException.throwIt((short) 0x6A03);
			return null;
		}
	}

	private static byte[] getDestBuffer(byte command) {
		switch (command & 0x0F) {
		case 0:
			return null;
		case 0xE:
			return cache1;
		case 0xF:
			return cache2;
		case 7:
			return transaction;
		default:
			ISOException.throwIt((short) 0x6A03);
			return null;
		}
	}

	private static short getDestOffset(byte[] buffer) {
		if (buffer == cache1) {
			return c1i;
		}
		if (buffer == cache2) {
			return c2i;
		}
		if (buffer == transaction) {
			return ti;
		}
		return 0;
	}

	private static void addDestOffset(byte[] buffer, short length) {
		if (buffer == cache1) {
			c1i += length;
		}
		if (buffer == cache2) {
			c2i += length;
		}
		if (buffer == transaction) {
			ti += length;
		}
	}

	private static short getInt(byte command) {
		switch (command & 0x0F) {
		case 0:
			intCache = 0;
			break;
		case 1:
			intCache = 1;
			break;
		case 2:
			intCache = 20;
			break;
		case 5:
			intCache = 32;
			break;
		case 6:
			intCache = 64;
			break;
		// case 8:
		// intCache = maxCache;
		// break;
		case 9:
			intCache = (short) (maxCache - intCache);
			break;
		case 0xC:
			intCache = (short) (script[si++] & 0x00FF);
			break;
		case 0xD:
			intCache = (short) (script[si++] & 0x00FF);
			intCache = (short) (intCache * 256 + (script[si++] & 0x00FF));
			break;
		case 0xB:
			intCache = bufferInt;
			break;
		default:
			ISOException.throwIt((short) 0x6A07);
			intCache = 0;
		}
		return intCache;
	}

	private static void getUpdateHash(byte[] dataBuf, short dataOffset,
			short dataLength, byte hashType) {
		switch (hashType) {
		case 2:
		case 0xD: // double sha-256, should hash again later
			ShaUtil.m_s_sha_256.update(dataBuf, dataOffset, dataLength);
			break;
		case 6:
			ShaUtil.m_keccak_256.update(dataBuf, dataOffset, dataLength);
			break;
		case 0x11:
			ShaUtil.m_blake3_256.update(dataBuf, dataOffset, dataLength);
			break;
		default:
			ISOException.throwIt((short) 0x6A0A);
		}
	}

	private static void getHash(byte[] dataBuf, short dataOffset,
			short dataLength, byte[] destBuf, short destOffset, byte hashType) {
		short length = 0;
		switch (hashType) {
		case 0:
			Util.arrayCopyNonAtomic(dataBuf, dataOffset, destBuf, destOffset,
					dataLength);
			length = dataLength;
			break;
		case 1:
			length = ShaUtil.SHA1(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 2:
			length = ShaUtil.S_SHA256(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 3:
			length = ShaUtil.SHA512(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 4:
			length = ShaUtil.Sha3256(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 5:
			length = ShaUtil.Sha3512(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 6:
			length = ShaUtil.Keccak256(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 7:
			length = ShaUtil.Keccak512(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 8:
			Ripemd.hash160(dataBuf, dataOffset, destBuf, destOffset);
			length = 20;
			break;
		case 9:
			ShaUtil.SHA256(dataBuf, dataOffset, dataLength, destBuf, destOffset);
			Ripemd.hash160(destBuf, destOffset, destBuf, destOffset);
			length = 20;
			break;
		case 0xA:
			length = ShaUtil.CRC16(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 0xB:
			length = ShaUtil.bech32_checksum(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0xC:
			length = ShaUtil.polyMod(dataBuf, dataOffset, dataLength, destBuf,
					destOffset);
			break;
		case 0xD:
			length = ShaUtil.S_DoubleSHA256(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0xE:
			length = ShaUtil.Blake2b256(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0xF:
			length = ShaUtil.Blake2b512(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0x10:
			length = ShaUtil.SHA512256(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0x11:
			length = ShaUtil.Blake3256(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		case 0x12:
			length = ShaUtil.bech32m_checksum(dataBuf, dataOffset, dataLength,
					destBuf, destOffset);
			break;
		default:
			ISOException.throwIt((short) 0x6A0A);
		}
		addDestOffset(destBuf, length);
	}

	private static byte[] getCharset(byte command) {
		switch (command & 0x0F) {
		case 0xF:
			return NumberUtil.binaryCharset;
		case 0xE:
			return NumberUtil.hexadecimalCharset;
		case 0xB:
			return NumberUtil.bcdCharset;
		case 0xD:
			return NumberUtil.decimalCharset;
		case 0x5:
			return NumberUtil.binary32Charset;
		case 0xC:
			return NumberUtil.base32BitcoinCashCharset;
		case 0x8:
			return NumberUtil.base58Charset;
		case 0x1:
			return cache1;
		default:
			ISOException.throwIt((short) 0x6A08);
			return null;
		}
	}

	private static short getBaseConvertInnerArgument(byte outArg) {
		short inArg = 0;
		if ((outArg & 0x1) != 0) {
			inArg |= NumberUtil.leftJustify;
		}
		if ((outArg & 0x2) != 0) {
			inArg |= NumberUtil.outLittleEndian;
		}
		if ((outArg & 0x4) != 0) {
			inArg |= NumberUtil.zeroInherit;
		}
		if ((outArg & 0x8) != 0) {
			inArg |= NumberUtil.bitLeftJustify8to5;
		}
		if ((outArg & 0x10) != 0) {
			inArg |= NumberUtil.inLittleEndian;
		}
		return inArg;
	}

}
