package coolbitx;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class Check {

	public static short takeString(byte[] buf, short offset, byte[] string) {
		if (Util.arrayCompare(buf, offset, string, Common.OFFSET_ZERO,
				(short) string.length) != 0) {
			ISOException.throwIt(ErrorMessage.CHECK_STRING_MISMATCH);
		}
		return (short) (offset + string.length);
	}

	public static void checkValue(short testee, short expect) {
		if (testee != expect) {
			ISOException.throwIt(ErrorMessage.CHECK_VALUE_MISMATCH);
		}
	}

	public static void checkValue(short testee, short expect, short errorCode) {
		if (testee != expect) {
			ISOException.throwIt(errorCode);
		}
	}

	public static void checkValue(byte[] buf, short offset, byte expect) {
		checkValue(buf[(short) (offset)], expect);
	}

	public static void checkArray(byte[] buf, short offset, byte[] buf2,
			short offset2, short length) {
		if (Util.arrayCompare(buf, offset, buf2, offset2, length) != 0) {
			ISOException.throwIt(ErrorMessage.CHECK_ARRAY_MISMATCH);
		}
	}

	public static void checkZero(byte[] buf, short offset, short length) {
		short endOffset = (short) (offset + length);
		for (short i = offset; i < endOffset; i++)
			if (buf[(short) (i)] != 0) {
				ISOException.throwIt(ErrorMessage.CHECK_NOT_ZERO);
			}
	}

	public static void checkRange(short min, short testee, short max) {
		if (testee < min || testee > max) {
			ISOException.throwIt(ErrorMessage.CHECK_OUT_OF_RANGE);
		}
	}
	
	public static void verifyCommand(byte[] buf, short apduOffset,
			short dataOffset, short dataLength) {
		// data=[apduData(Variety)][appId(20B)[rightJustifiedSignature(72B)]
		if (dataLength < 92) {
			ISOException.throwIt(ErrorMessage.CMD_DATA_TOO_SHORT);
		}
		if (!CardInfo.is(CardInfo.NONCE_ACTI)) {
			ISOException.throwIt(ErrorMessage.CMD_NONCE_NOT_ACTIVATED);
		}
		short signOffset = (short) (dataOffset + dataLength - 72);
		short appIdOffset = (short) (signOffset - 20);
		dataLength -= 92;
		byte currentDevice = DeviceManager.isRegistered(buf, appIdOffset);
		if (currentDevice == 0) {
			ISOException.throwIt(ErrorMessage.CMD_APP_NOT_REGISTERED);
		}
		DeviceManager.setCurrentDevice(currentDevice);
		CardInfo.set(CardInfo.NONCE_ACTI, false);
		ShaUtil.m_sha_256.update(buf, apduOffset, (short) 4);
		ShaUtil.m_sha_256.update(buf, dataOffset, dataLength);
		boolean isVerified = SignUtil
				.isVerifiedFixedLength(Main.nonce, (short) 0, (short) 8, buf,
						signOffset, DeviceManager.getAppPublicKey());
		Common.clearArray(Main.nonce);
		if (!isVerified) {
			ISOException.throwIt(ErrorMessage.CMD_SIGNATURE_INVALID);
		}
	}
}
