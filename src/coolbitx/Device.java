/*
 * Copyright (C) CoolBitX Technology - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPublicKey;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Device {
	private static boolean paired = false;
	private static boolean freezed = false;

	private static OwnerPIN pin;
	private static byte[] password;
	private static final byte DEVICE_NUM = 3;
	private static boolean[] pairedList;
	public static byte[] appPublicKeyList;
	private static byte[] appIdList;
	private static byte[] nameList;

	public static short backupData(byte[] destBuf, short destOffset) {
		short initOffset = destOffset;
		destBuf[destOffset++] = Common.booleanToByte(paired);
		destBuf[destOffset++] = Common.booleanToByte(freezed);
		destOffset = Util.arrayCopyNonAtomic(password, Common.OFFSET_ZERO,
				destBuf, destOffset, Common.LENGTH_PASSWORD);
		for (byte i = 0; i < pairedList.length; i++) {
			destBuf[destOffset++] = Common
					.booleanToByte(pairedList[(short) (i)]);
		}
		destOffset = Util.arrayCopyNonAtomic(appPublicKeyList,
				Common.OFFSET_ZERO, destBuf, destOffset,
				(short) (DEVICE_NUM * Common.LENGTH_PUBLICKEY));
		destOffset = Util.arrayCopyNonAtomic(appIdList, Common.OFFSET_ZERO,
				destBuf, destOffset,
				(short) (DEVICE_NUM * Common.LENGTH_APP_ID));
		destOffset = Util.arrayCopyNonAtomic(nameList, Common.OFFSET_ZERO,
				destBuf, destOffset, (short) (DEVICE_NUM * Common.LENGTH_NAME));
		// destBuf[destOffset++] = retryTime;
		destBuf[destOffset++] = pin.getTriesRemaining();
		return (short) (destOffset - initOffset);
	}

	public static short recoverData(byte[] buf, short offset) {
		paired = Common.byteToBoolean(buf[offset++]);
		freezed = Common.byteToBoolean(buf[offset++]);
		pin.update(buf, offset, Common.LENGTH_PASSWORD);
		Util.arrayCopyNonAtomic(buf, offset, password, Common.OFFSET_ZERO,
				Common.LENGTH_PASSWORD);
		offset += Common.LENGTH_PASSWORD;
		for (byte i = 0; i < pairedList.length; i++) {
			pairedList[i] = Common.byteToBoolean(buf[offset++]);
		}
		Util.arrayCopyNonAtomic(buf, offset, appPublicKeyList,
				Common.OFFSET_ZERO, (short) appPublicKeyList.length);
		offset += appPublicKeyList.length;
		Util.arrayCopyNonAtomic(buf, offset, appIdList, Common.OFFSET_ZERO,
				(short) appIdList.length);
		offset += appIdList.length;
		Util.arrayCopyNonAtomic(buf, offset, nameList, Common.OFFSET_ZERO,
				(short) nameList.length);
		offset += nameList.length;
		offset++; // ignore retryTime
		return offset;
	}

	public static void init() {
		pin = new OwnerPIN(Common.PWD_TRY, Common.LENGTH_PASSWORD);
		password = new byte[Common.LENGTH_PASSWORD];
		pairedList = new boolean[DEVICE_NUM];
		appPublicKeyList = new byte[(short) (DEVICE_NUM * Common.LENGTH_PUBLICKEY)];
		appIdList = new byte[(short) (DEVICE_NUM * Common.LENGTH_APP_ID)];
		nameList = new byte[(short) (DEVICE_NUM * Common.LENGTH_NAME)];
	}

	public static void uninit() {
		pin = null;
		password = null;
		pairedList = null;
		appPublicKeyList = null;
		appIdList = null;
		nameList = null;
	}

	public static void reset() {
		Common.clearArray(pairedList);
		paired = false;
		freezed = false;
		pin.resetAndUnblock();
	}

	public static short getCardInfo(byte[] buf, short offset) {
		buf[offset++] = Common.booleanToByte(paired);
		buf[offset++] = Common.booleanToByte(freezed);
		buf[offset++] = pin.getTriesRemaining();
		return offset;
	}

	public static boolean isFull() {
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			if (!isPaired(i)) {
				return false;
			}
		}
		return true;
	}

	public static byte isRegistered(byte[] buf, short offset) {
		byte regIndex = 0;
		for (byte index = 1; index <= DEVICE_NUM; index++) {
			if (isPaired(index)
					&& Util.arrayCompare(buf, offset, appIdList,
							getAppId(index), Common.LENGTH_APP_ID) == 0) {
				regIndex = index;
				break;
			}
		}
		return regIndex;
	}

	public static short getDeviceList(byte[] destBuf, short destOffset) {
		short listOffset = destOffset;
		for (byte index = 1; index <= DEVICE_NUM; index++) {
			if (isPaired(index)) {
				listOffset = Util.arrayCopyNonAtomic(appIdList,
						(short) ((index - 1) * Common.LENGTH_APP_ID), destBuf,
						listOffset, Common.LENGTH_APP_ID);
				listOffset = Util.arrayCopyNonAtomic(nameList,
						(short) ((index - 1) * Common.LENGTH_NAME), destBuf,
						listOffset, Common.LENGTH_NAME);
			}
		}
		return (short) (listOffset - destOffset);
	}

	public static void setDevice(byte[] buf, short offset, byte[] destBuf,
			short destOffset) {
		short keyOffset = (short) (offset + Common.LENGTH_PASSWORD);
		short nameOffset = (short) (keyOffset + Common.LENGTH_PUBLICKEY);
		if (!paired) {
			setPassword(buf, offset);
		} else if (pin.getTriesRemaining() <= 0) {
			ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
		} else if (!pin.check(buf, offset, Common.LENGTH_PASSWORD)) {
			if (pin.getTriesRemaining() == 0) {
				freezed = true;
			}
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		} // password enter correct
		ShaUtil.SHA1(buf, keyOffset, Common.LENGTH_PUBLICKEY, destBuf,
				destOffset);
		short deviceIndex = isRegistered(destBuf, destOffset);
		if (0 != deviceIndex) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		for (byte index = 1; index <= DEVICE_NUM; index++) {
			if (!isPaired(index)) {
				setAppPublicKey(buf, keyOffset, index);
				setAppId(destBuf, destOffset, index);
				setName(buf, nameOffset, index);
				registerDevice(index);
				paired = true;
				break;
			}
		}
	}

	public static boolean isFreezed() {
		return freezed;
	}

	public static void setFreezed(boolean status) {
		if (!status) {
			pin.resetAndUnblock();
			pin.update(password, Common.OFFSET_ZERO, Common.LENGTH_PASSWORD);
		}
		freezed = status;
	}

	public static boolean isPaired(short index) {
		return pairedList[(short) (index - 1)];
	}

	public static void registerDevice(short index) {
		pairedList[(short) (index - 1)] = true;
	}

	public static void removeDevice(short index) {
		pairedList[(short) (index - 1)] = false;
	}

	public static short getPassword(byte[] destBuf, short destOffset) {
		if (!paired) {
			ISOException.throwIt((short) 0x6B0C);
		}
		if (freezed) {
			ISOException.throwIt((short) 0x6B0D);
		}
		NonceUtil.randomRange(password, Common.OFFSET_ZERO,
				Common.LENGTH_PASSWORD, NonceUtil.PWD_MAX, NonceUtil.PWD_MIN);
		NumberUtil.baseConvert(password, Common.OFFSET_ZERO,
				Common.LENGTH_PASSWORD, NumberUtil.binaryCharset, password,
				Common.OFFSET_ZERO, Common.LENGTH_PASSWORD,
				NumberUtil.bcdCharset, NumberUtil.inBuffered);
		if (password[0] == 0) {
			password[0] = (byte) 0xff;
		}
		if ((password[0] & 0xF0) == 0) {
			password[0] |= 0xF0;
		}
		pin.update(password, Common.OFFSET_ZERO, Common.LENGTH_PASSWORD);
		Util.arrayCopyNonAtomic(password, Common.OFFSET_ZERO, destBuf,
				destOffset, Common.LENGTH_PASSWORD);
		return Common.LENGTH_PASSWORD;
	}

	public static void setPassword(byte[] buf, short offset) {
		Util.arrayCopyNonAtomic(buf, offset, password, Common.OFFSET_ZERO,
				Common.LENGTH_PASSWORD);
		pin.update(buf, offset, Common.LENGTH_PASSWORD);
	}

	public static short getAppPublicKeyByte(short index) {
		return (short) ((index - 1) * Common.LENGTH_PUBLICKEY);
	}

	public static ECPublicKey getAppPublicKey(short index) {
		return KeyUtil.getPubKey(appPublicKeyList,
				(short) ((index - 1) * Common.LENGTH_PUBLICKEY));
	}

	public static void setAppPublicKey(byte[] buf, short offset, short index) {
		Util.arrayCopyNonAtomic(buf, offset, appPublicKeyList,
				(short) ((index - 1) * Common.LENGTH_PUBLICKEY),
				Common.LENGTH_PUBLICKEY);
	}

	public static short getAppId(short index) {
		return (short) ((index - 1) * Common.LENGTH_APP_ID);
	}

	public static void setAppId(byte[] buf, short offset, short index) {
		Util.arrayCopyNonAtomic(buf, offset, appIdList,
				(short) ((index - 1) * Common.LENGTH_APP_ID),
				Common.LENGTH_APP_ID);
	}

	public short getName(short index) {
		return (short) ((index - 1) * Common.LENGTH_NAME);
	}

	public static void setName(byte[] buf, short offset, short index) {
		Util.arrayCopyNonAtomic(buf, offset, nameList,
				(short) ((index - 1) * Common.LENGTH_NAME), Common.LENGTH_NAME);
	}
}
