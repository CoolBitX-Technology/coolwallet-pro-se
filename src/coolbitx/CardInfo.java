/**
 * 
 */
package coolbitx;

import com.nxp.id.jcopx.security.ConstantX;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class CardInfo {
	private static byte displayType;
	private static byte walletStatus;

	private static final byte balanceLength = (byte) (Common.DISPLAY_NUM * 9);
	private static byte[] balance;

	private static final short totalIndexIdLength = 240;
	private static byte[] indexId;

	private static byte[] stateArray;
	private static final short A_LENGTH = 4;
	public static final short DEVICE = 0;
	public static final short TRANSCATION_STATE = 1;
	public static final short MESSAGE_TYPE = 2;
	public static final short EXPECT_READ_TYPE = 3;

	public static void set(short type, byte status) {
		if (type > A_LENGTH || type < 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} else {
			stateArray[(short) (type)] = status;
		}
	}

	public static byte get(short type) {
		byte status = 0;
		if (type > B_LENGTH) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} else {
			status = stateArray[(short) (type)];
		}
		return status;
	}

	private static short[] stateBoolean;
	private static final short B_LENGTH = 13;
	public static final short NONCE_ACTI = 0;
	public static final short AUTH_GET_KEY = 1;
	public static final short AUTH_TX = 2;
	public static final short SIGN_AESKEY_VALID = 3;
	public static final short EX_ADDR_EXIST = 4;
	public static final short SELFBUILD = 5;
	// public static final short TESTNET = 6;
	public static final short SECOND_TOKEN = 7;
	public static final short FULL_DATA = 8;
	public static final short OMNI_TX = 9;
	public static final short ACTIVE_READTYPE = 10;
	public static final short SELFBUILD_2 = 11;
	public static final short IS_BNB_TOKEN = 12;

	public static void set(short type, boolean status) {
		if (type > B_LENGTH || type < 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if (status) {
			stateBoolean[type] = ConstantX.TRUE16;
		} else {
			stateBoolean[type] = ConstantX.FALSE16;
		}
	}

	public static boolean is(short type) {
		if (type > B_LENGTH) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		boolean result = false;
		if (stateBoolean[type] == ConstantX.TRUE16) {
			result = true;
		} else if (stateBoolean[type] == ConstantX.FALSE16) {
			result = false;
		} else {
			ISOException.throwIt((short) 0x6f11);
		}
		return result;
	}

	public static void init() {
		balance = new byte[(short) (balanceLength)];
		indexId = new byte[(short) (totalIndexIdLength)];
		stateBoolean = JCSystem.makeTransientShortArray(B_LENGTH,
				JCSystem.CLEAR_ON_DESELECT);
		stateArray = JCSystem.makeTransientByteArray(A_LENGTH,
				JCSystem.CLEAR_ON_DESELECT);
	}

	public static void reset() {
		for (byte i = 0; i < B_LENGTH; i++) {
			if (stateBoolean[i] == 0) {
				stateBoolean[i] = ConstantX.FALSE16;
			}
		}
	}

	public static void uninit() {
		balance = null;
		indexId = null;
		stateBoolean = null;
		stateArray = null;
	}

	public static short getCardInfo(byte[] destBuf, short destOffset) {
		short accountDigest = 5;
		short accountDigest20Bytes = 20;
		boolean isWalletCreated = walletStatus != Common.WALLET_CREATED;
		if (isWalletCreated) {
			destBuf[destOffset++] = (byte) 0;
			Util.arrayFillNonAtomic(destBuf, destOffset, accountDigest,
					(byte) 0);
		} else {
			destBuf[destOffset++] = (byte) 1;
			Bip32.getAccountDigest(destBuf, destOffset, accountDigest);
		}
		destOffset += accountDigest;
		destBuf[destOffset++] = displayType;
		destBuf[destOffset++] = Bip32Ed25519.isInit();
		if (isWalletCreated) {
			Util.arrayFillNonAtomic(destBuf, destOffset, accountDigest20Bytes,
					(byte) 0);
		} else {
			Bip32.getAccountDigest(destBuf, destOffset, accountDigest20Bytes);
		}
		destOffset += accountDigest20Bytes;
		return destOffset;
	};

	public static byte getDisplayType() {
		return displayType;
	}

	public static void setDisplayType(byte type, boolean force) {
		if (!force && type == displayType) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if (type == 0 || type == 1) {
			displayType = type;
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
	}

	public static void checkWalletStatusNotEqual(byte expectStatus) {
		if (walletStatus == expectStatus) {
			ISOException.throwIt(ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
		}
	}

	public static void checkWalletStatusEqual(byte expectStatus) {
		if (walletStatus != expectStatus) {
			ISOException.throwIt(ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
		}
	}

	public static byte getWalletStatus() {
		return walletStatus;
	}

	public static void setWalletStatus(byte status) {
		walletStatus = status;
	}

	public static byte getBalance(byte[] destBuf, short destOffset) {
		Util.arrayCopyNonAtomic(balance, Common.OFFSET_ZERO, destBuf,
				destOffset, (short) 36);
		return (short) 36;
	}

	public static void setBalance(byte[] buf, short offset, short length) {
		Util.arrayCopyNonAtomic(buf, offset, balance, Common.OFFSET_ZERO,
				length);
	}

	public static short getIndexId(byte[] destBuf, short destOffset,
			short length) {
		Util.arrayCopyNonAtomic(indexId, Common.OFFSET_ZERO, destBuf,
				destOffset, length);
		return length;
	}

	public static void setIndexId(byte[] buf, short offset, short length) {
		Util.arrayCopyNonAtomic(buf, offset, indexId, Common.OFFSET_ZERO,
				length);
	}

	public static void defaultSettings() {
		Common.clearArray(balance);
		Common.clearArray(indexId);
		Common.clearArray(stateBoolean);
		Common.clearArray(stateArray);
		// bitcoin
		// balance[(short)(9 * 0)] = Common.COINTYPE_BTC;
		// indexId[(short)(3 * 0)] = Common.COINTYPE_BTC;
		// ethereum
		balance[(short) (9 * 1)] = Common.COINTYPE_ETH;
		indexId[(short) (3 * 1)] = Common.COINTYPE_ETH;
		// litecoin
		balance[(short) (9 * 2)] = Common.COINTYPE_LTC;
		indexId[(short) (3 * 2)] = Common.COINTYPE_LTC;
		// ripple
		balance[(short) (9 * 3)] = Common.COINTYPE_XRP;
		indexId[(short) (3 * 3)] = Common.COINTYPE_XRP;
		// bitcoin cash
		indexId[(short) (3 * 4)] = Common.COINTYPE_BCH;
		// amount only
		displayType = 1;
		walletStatus = Common.WALLET_EMPTY;
	}
}
