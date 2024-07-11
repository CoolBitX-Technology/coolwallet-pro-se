package coolbitx;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class Check {

	public static short takeString(byte[] buf, short offset, byte[] string) {
		if (Util.arrayCompare(buf, offset, string, Common.OFFSET_ZERO,
				(short) string.length) != 0) {
			ISOException.throwIt((short) 0x6201);
		}
		return (short) (offset + string.length);
	}

	public static void checkValue(short testee, short expect) {
		if (testee != expect) {
			ISOException.throwIt((short) 0x6204);
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
			ISOException.throwIt((short) 0x6202);
		}
	}

	public static void checkZero(byte[] buf, short offset, short length) {
		short endOffset = (short) (offset + length);
		for (short i = offset; i < endOffset; i++)
			if (buf[(short) (i)] != 0) {
				ISOException.throwIt((short) 0x6203);
			}
	}

	public static void checkRange(short min, short testee, short max) {
		if (testee < min || testee > max) {
			ISOException.throwIt((short) 0x6205);
		}
	}
	
	public static void verifyCommand(byte[] buf, short apduOffset,
			short dataOffset, short dataLength) {
		// data=[apduData(Variety)][appId(20B)[rightJustifiedSignature(72B)]

		if (dataLength < 92) {
			ISOException.throwIt((short) 0x609C);
		}
		if (!CardInfo.is(CardInfo.NONCE_ACTI)) {
			ISOException.throwIt((short) 0x609F);
		}
		short signOffset = (short) (dataOffset + dataLength - 72);
		short appIdOffset = (short) (signOffset - 20);
		dataLength -= 92;
		byte currentDevice = Device.isRegistered(buf, appIdOffset);
		if (currentDevice == 0) {
			ISOException.throwIt((short) 0x609D);
		}

		CardInfo.set(CardInfo.NONCE_ACTI, false);
		ShaUtil.m_sha_256.update(buf, apduOffset, (short) 4);
		ShaUtil.m_sha_256.update(buf, dataOffset, dataLength);
		boolean isVerified = SignUtil
				.isVerifiedFixedLength(Main.nonce, (short) 0, (short) 8, buf,
						signOffset, Device.getAppPublicKey());
		Common.clearArray(Main.nonce);
		if (!isVerified) {
			ISOException.throwIt((short) 0x609E);
		}
	}
}
