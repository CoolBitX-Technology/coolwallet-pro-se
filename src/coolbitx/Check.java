package coolbitx;

import javacard.framework.ISOException;

public class Check {

	public static void checkValue(short testee, short expect, short errorCode) {
		if (testee != expect) {
			ISOException.throwIt(errorCode);
		}
	}

	public static void checkRange(short min, short testee, short max,
			short errorCode) {
		if (testee < min || testee > max) {
			ISOException.throwIt(errorCode);
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
