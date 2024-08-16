/*
 * Copyright (C) CoolBitX Technology - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPublicKey;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class DeviceManager {
	private static final byte DEVICE_NUM = 3;
	private static byte[] state;
	private static final short STATE_LENGTH = 1;
	private static final short CURRENT_DEVICE = 0;

	private static byte[] defaultPassword = { (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff };

	private static Device[] devices;
	private static PinCode pinCode;

	private static class PinCode extends OwnerPIN {
		private byte[] password;
		private byte maxPINSize;
		private boolean freezed = false;

		public PinCode(byte tryLimit, byte maxPINSize) {
			super(tryLimit, maxPINSize);
			this.maxPINSize = maxPINSize;
			password = new byte[maxPINSize];
		}

		public void update(byte[] buf, short offset, byte len) {
			if (len > maxPINSize) {
				ISOException.throwIt(ErrorMessage._6A00);
			}
			super.update(buf, offset, len);
			password = new byte[len];
			Util.arrayCopyNonAtomic(buf, offset, password, Common.OFFSET_ZERO,
					len);
		}

		public byte getTriesRemaining() {
			return super.getTriesRemaining();
		}

		public boolean check(byte[] pin, short offset, byte length) {
			boolean result = super.check(pin, offset, length);
			if (this.getTriesRemaining() == 0) {
				freezed = true;
			}
			return result;
		}

		public void resetAndUnblock() {
			super.resetAndUnblock();
			freezed = false;
			this.update(password, Common.OFFSET_ZERO, (byte) password.length);
		}

		private short getPassword(byte[] destBuf, short destOffset) {
			return Util.arrayCopyNonAtomic(this.password, Common.OFFSET_ZERO,
					destBuf, destOffset, (short) password.length);
		}

		public boolean isFreezed() {
			return freezed;
		}

		public void setFreezed(boolean status) {
			if (!status) {
				pinCode.resetAndUnblock();
			}
			freezed = status;
		}

	}

	private static class Device {
		private boolean hasData;
		private byte[] publicKey;
		private byte[] id;
		private byte[] name;

		Device() {
			hasData = false;
			publicKey = new byte[Common.LENGTH_PUBLICKEY];
			id = new byte[Common.LENGTH_APP_ID];
			name = new byte[Common.LENGTH_NAME];
		}

		private void remove() {
			hasData = false;
			Common.clearArray(publicKey);
			Common.clearArray(id);
			Common.clearArray(name);
		}

		public boolean isDataSet() {
			return hasData;
		}

		public void setDataStatus(boolean hasData) {
			this.hasData = hasData;
		}

		public short getPublicKey(byte[] destBuf, short destOffset) {
			return Util.arrayCopyNonAtomic(publicKey, Common.OFFSET_ZERO,
					destBuf, destOffset, Common.LENGTH_PUBLICKEY);
		}

		public void setPublicKey(byte[] appPublicKey, short appPublicKeyOffset) {
			Util.arrayCopyNonAtomic(appPublicKey, appPublicKeyOffset,
					publicKey, Common.OFFSET_ZERO, Common.LENGTH_PUBLICKEY);
		}

		public short getId(byte[] destBuf, short destOffset) {
			return Util.arrayCopyNonAtomic(id, Common.OFFSET_ZERO, destBuf,
					destOffset, Common.LENGTH_APP_ID);
		}

		public void setAppId(byte[] appId, short appIdOffset) {
			Util.arrayCopyNonAtomic(appId, appIdOffset, id, Common.OFFSET_ZERO,
					Common.LENGTH_APP_ID);
		}

		public short getName(byte[] destBuf, short destOffset) {
			return Util.arrayCopyNonAtomic(name, Common.OFFSET_ZERO, destBuf,
					destOffset, Common.LENGTH_NAME);
		}

		public void setName(byte[] appName, short appNameOffset) {
			Util.arrayCopyNonAtomic(appName, appNameOffset, name,
					Common.OFFSET_ZERO, Common.LENGTH_NAME);
		}

		public void replace(Device device) {
			this.hasData = device.hasData;
			Util.arrayCopyNonAtomic(device.publicKey, Common.OFFSET_ZERO, publicKey, Common.OFFSET_ZERO,
					Common.LENGTH_PUBLICKEY);
			Util.arrayCopyNonAtomic(device.id, Common.OFFSET_ZERO, id, Common.OFFSET_ZERO, Common.LENGTH_APP_ID);
			Util.arrayCopyNonAtomic(device.name, Common.OFFSET_ZERO, name, Common.OFFSET_ZERO, Common.LENGTH_NAME);

		}

		private boolean isRecognized(byte[] appId, short appIdOffset) {
			if (!hasData) {
				return false;
			}
			return Util.arrayCompare(id, Common.OFFSET_ZERO, appId,
					appIdOffset, Common.LENGTH_APP_ID) == 0;
		}
	}

	public static short backupData(byte[] destBuf, short destOffset) {
		short initOffset = destOffset;
		destBuf[destOffset++] = Common.booleanToByte(isPaired());
		destBuf[destOffset++] = Common.booleanToByte(pinCode.isFreezed());
		destOffset = pinCode.getPassword(destBuf, destOffset);
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			destBuf[destOffset++] = Common.booleanToByte(getDevice(i)
					.isDataSet());
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			destOffset = getDevice(i).getPublicKey(destBuf, destOffset);
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			destOffset = getDevice(i).getId(destBuf, destOffset);
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			destOffset = getDevice(i).getName(destBuf, destOffset);
		}
		destBuf[destOffset++] = pinCode.getTriesRemaining();
		return (short) (destOffset - initOffset);
	}

	public static short recoverData(byte[] buf, short offset) {
		// paired = Common.byteToBoolean(buf[offset++]);
		offset++;
		pinCode.setFreezed(Common.byteToBoolean(buf[offset++]));
		pinCode.update(buf, offset, Common.LENGTH_PASSWORD);
		offset += Common.LENGTH_PASSWORD;
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			getDevice(i).setDataStatus(Common.byteToBoolean(buf[offset++]));
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			getDevice(i).setPublicKey(buf, offset);
			offset += Common.LENGTH_PUBLICKEY;
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			getDevice(i).setAppId(buf, offset);
			offset += Common.LENGTH_APP_ID;
		}
		for (byte i = 1; i <= DEVICE_NUM; i++) {
			getDevice(i).setName(buf, offset);
			offset += Common.LENGTH_NAME;
		}
		for (byte i = buf[offset++]; i < Common.PWD_TRY; i++) {
			pinCode.check(defaultPassword, Common.OFFSET_ZERO,
					Common.LENGTH_PASSWORD);
		}
		return offset;
	}

	public static void init(boolean initWithRam) {
		pinCode = new PinCode(Common.PWD_TRY, Common.LENGTH_PASSWORD);
		if (initWithRam) {
			state = JCSystem.makeTransientByteArray(STATE_LENGTH,
					JCSystem.CLEAR_ON_DESELECT);
		} else {
			state = new byte[STATE_LENGTH];
		}

		devices = new Device[DEVICE_NUM];
		for (byte i = 0; i < DEVICE_NUM; i++) {
			devices[i] = new Device();
		}
	}

	public static void uninit() {
		pinCode = null;
		state = null;
		devices = null;
	}

	public static void reset() {
		pinCode.resetAndUnblock();
		Common.clearArray(state);
		for (byte i = 0; i < DEVICE_NUM; i++) {
			devices[i].remove();
		}
	}

	public static short getCardInfo(byte[] buf, short offset) {
		buf[offset++] = Common.booleanToByte(isPaired());
		buf[offset++] = Common.booleanToByte(pinCode.isFreezed());
		buf[offset++] = pinCode.getTriesRemaining();
		return offset;
	}

	public static boolean isFull() {
		for (byte i = 0; i < DEVICE_NUM; i++) {
			if (!devices[i].isDataSet()) {
				return false;
			}
		}
		return true;
	}

	public static boolean isPaired() {
		for (byte i = 0; i < DEVICE_NUM; i++) {
			if (devices[i].isDataSet()) {
				return true;
			}
		}
		return false;
	}

	/*
	 * The buf array contains app ID. If the card recognizes this ID, it will
	 * return a corresponding value ranging from 1, 2, to DEVICE_NUM . If not
	 * recognize will return 0;
	 */
	public static byte isRegistered(byte[] buf, short offset) {
		byte regIndex = 0;
		for (byte index = 1; index <= DEVICE_NUM; index++) {
			if (getDevice(index).isRecognized(buf, offset)) {
				regIndex = index;
				break;
			}
		}
		return regIndex;
	}

	public static short getDeviceList(byte[] destBuf, short destOffset) {
		short listOffset = destOffset;
		for (byte index = 1; index <= DEVICE_NUM; index++) {
			Device device = getDevice(index);
			if (device.hasData) {
				listOffset = device.getId(destBuf, listOffset);
				listOffset = device.getName(destBuf, listOffset);
			}
		}
		return (short) (listOffset - destOffset);
	}

	private static void validateRegisterPrecondition(byte[] buf, short offset, byte[] destBuf, short destOffset) {
		short keyOffset = (short) (offset + Common.LENGTH_PASSWORD);
		short nameOffset = (short) (keyOffset + Common.LENGTH_PUBLICKEY);

		if (!isPaired()) {
			setPassword(buf, offset);
		} else if (pinCode.getTriesRemaining() <= 0) {
			ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
		} else if (!pinCode.check(buf, offset, Common.LENGTH_PASSWORD)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		} // password enter correct


		ShaUtil.SHA1(buf, keyOffset, Common.LENGTH_PUBLICKEY, destBuf,
				destOffset);
		short deviceIndex = isRegistered(destBuf, destOffset);
		if (0 != deviceIndex) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}

	public static void setDevice(byte[] buf, short offset, byte[] destBuf, short destOffset) {
		short keyOffset = (short) (offset + Common.LENGTH_PASSWORD);
		short nameOffset = (short) (keyOffset + Common.LENGTH_PUBLICKEY);

		validateRegisterPrecondition(buf, offset, destBuf, destOffset);

		for (byte index = 1; index <= DEVICE_NUM; index++) {
			Device device = getDevice(index);
			if (!device.isDataSet()) {
				setCurrentDevice(index);
				device.setPublicKey(buf, keyOffset);
				device.setAppId(destBuf, destOffset);
				device.setName(buf, nameOffset);
				device.setDataStatus(true);
				break;
			}
		}
	}

	public static void addOrReplaceOldestDevice(byte[] buf, short offset, byte[] destBuf,
			short destOffset) {
		short keyOffset = (short) (offset + Common.LENGTH_PASSWORD);
		short nameOffset = (short) (keyOffset + Common.LENGTH_PUBLICKEY);

		validateRegisterPrecondition(buf, offset, destBuf, destOffset);

		byte registeredDeviceCount = 0;
		while (registeredDeviceCount < DEVICE_NUM && devices[registeredDeviceCount].isDataSet()) {
			registeredDeviceCount++;
		}

		Device device;
		if (registeredDeviceCount < DEVICE_NUM) {
			// device list do not reach limit
			device = devices[registeredDeviceCount];
		} else {
			// device list reached limit
			byte lastIndex = DEVICE_NUM - 1;
			for (byte i = 0; i < lastIndex; i++) {
				Device prevDevice = devices[i];
				Device nextDevice = devices[i + 1];
				prevDevice.replace(nextDevice);
			}
			device = devices[lastIndex];
		}

		// set device to a index
		setCurrentDevice(registeredDeviceCount);
		device.setPublicKey(buf, keyOffset);
		device.setAppId(destBuf, destOffset);
		device.setName(buf, nameOffset);
		device.setDataStatus(true);
	}

	public static boolean isFreezed() {
		return pinCode.isFreezed();
	}

	public static void setFreezed(boolean status) {
		pinCode.setFreezed(status);
	}

	public static void removeDevice(byte index) {
		if (state[CURRENT_DEVICE] == index) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		getDevice(index).remove();
	}

	public static short getPassword(byte[] destBuf, short destOffset) {
		if (!isPaired()) {
			ISOException.throwIt((short) 0x6B0C);
		}
		if (pinCode.isFreezed()) {
			ISOException.throwIt((short) 0x6B0D);
		}
		byte[] password = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short passwordOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_PASSWORD);
		NonceUtil.randomRange(password, passwordOffset, Common.LENGTH_PASSWORD,
				NonceUtil.PWD_MAX, NonceUtil.PWD_MIN);
		NumberUtil.baseConvert(password, passwordOffset,
				Common.LENGTH_PASSWORD, NumberUtil.binaryCharset, password,
				passwordOffset, Common.LENGTH_PASSWORD, NumberUtil.bcdCharset,
				NumberUtil.inBuffered);
		if (password[passwordOffset] == 0) {
			password[passwordOffset] = (byte) 0xff;
		}
		if ((password[passwordOffset] & 0xF0) == 0) {
			password[passwordOffset] |= 0xF0;
		}
		pinCode.update(password, Common.OFFSET_ZERO, Common.LENGTH_PASSWORD);
		Util.arrayCopyNonAtomic(password, Common.OFFSET_ZERO, destBuf,
				destOffset, Common.LENGTH_PASSWORD);
		return Common.LENGTH_PASSWORD;
	}

	public static void setPassword(byte[] buf, short offset) {
		pinCode.update(buf, offset, Common.LENGTH_PASSWORD);
	}

	public static void getAppPublicKeyAsByteArray(byte[] destBuf,
			short destOffset) {
		getCurrentDevice().getPublicKey(destBuf, destOffset);
	}

	public static ECPublicKey getAppPublicKey() {
		byte[] appPublicKey = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short appPublicKeyOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_PUBLICKEY);
		getCurrentDevice().getPublicKey(appPublicKey, appPublicKeyOffset);
		ECPublicKey ecKey = KeyUtil.getPubKey(appPublicKey, appPublicKeyOffset);
		WorkCenter.release(WorkCenter.WORK, Common.LENGTH_PUBLICKEY);
		return ecKey;
	}

	// private static short getAppIdOffset(byte index) {
	// return (short) ((index - 1) * Common.LENGTH_APP_ID);
	// }

	public static void setAppId(byte[] buf, short offset) {
		getCurrentDevice().setAppId(buf, offset);
	}

	public static void setName(byte[] buf, short offset) {
		getCurrentDevice().setName(buf, offset);
	}

	private static Device getDevice(byte index) {
		if (index > DEVICE_NUM) {
			ISOException.throwIt(ErrorMessage._6fff);
		}
		return devices[index - 1];
	}

	private static Device getCurrentDevice() {
		if (state[CURRENT_DEVICE] == 0) {
			ISOException.throwIt(ErrorMessage._6fff);
		}
		return devices[state[CURRENT_DEVICE] - 1];
	}

	public static void setCurrentDevice(byte currentDevice) {
		state[CURRENT_DEVICE] = currentDevice;
	}
}
