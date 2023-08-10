/*
 * Copyright (C) CoolBitX Technology - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package coolbitx;

import javacard.framework.Util;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Common {

	public static final short OFFSET_ZERO = 0;
	public static final short OFFSET_ONE = 1;
	public static final short LENGTH_NONCE = 8;
	public static final byte PWD_TRY = 5;
	public static final byte LENGTH_PASSWORD = 4;
	public static final short LENGTH_COMPRESS_PUBLICKEY = 33;
	public static final short LENGTH_PUBLICKEY = 65;
	public static final short LENGTH_PRIVATEKEY = 32;
	public static final short LENGTH_CHAINCODE = 32;
	public static final short LENGTH_APP_ID = 20;
	public static final short LENGTH_IV = 16;
	public static final short LENGTH_MAC = 20;
	public static final short LENGTH_NAME = 30;
	public static final short LENGTH_SEED = 64;
	public static final short LENGTH_WAVES_SEED = 32;
	public static final short LENGTH_BIP32ED25519KEY = 96;
	public static final short LENGTH_SHA256 = 32;
	public static final short LENGTH_SHA512 = 64;
	public static final short LENGTH_ENC_PERSO_DATA = 176;
	public static final short LENGTH_ECIES_PERSO_DATA = 261; // 65+20+LENGTH_ENC_PERSO_DATA

	// tx status
	public static final byte STATE_NONE = 0;
	public static final byte STATE_PREPARE = 1;
	public static final byte STATE_WAITING_AUTH = 2;
	public static final byte STATE_TX = 3;
	// wallet status
	public static final byte WALLET_EMPTY = 0;
	public static final byte WALLET_DISPLAY = 1;
	public static final byte WALLET_CALCULATION = 2;
	public static final byte WALLET_CREATED = 3;

	// balance
	public static final short DISPLAY_NUM = 4;

	// coin type
	public static final byte COINTYPE_BTC = (byte) 0x00;
	public static final byte COINTYPE_TESTNET = (byte) 0x01;
	public static final byte COINTYPE_LTC = (byte) 0x02;
	public static final byte COINTYPE_ETH = (byte) 0x3c;
	public static final byte COINTYPE_XRP = (byte) 0x90;
	public static final byte COINTYPE_BCH = (byte) 0x91;
	public static final byte COINTYPE_ZEN = (byte) 0x79;
	public static final byte COINTYPE_EOS = (byte) 0xc2;
	public static final byte COINTYPE_BNB = (byte) 0xca;
	public static final byte COINTYPE_ICX = (byte) 0x4a;
	public static final byte COINTYPE_KINESIS = (byte) 0x94;

	public static final byte TYPE_UNKNOWN = 0;
	public static final byte TYPE_P2PKH = 1;
	public static final byte TYPE_P2SH = 2;
	public static final byte TYPE_P2WPKH = 3;

	// address format
	// public static final byte ADDR_BTC = 0x00;
	// public static final byte ADDR_LTC = 0x01;
	// public static final byte ADDR_NEW_LTC = 0x02;
	// public static final byte ADDR_BCH = 0x03;
	// public static final byte ADDR_NEW_BCH = 0x04;
	// public static final byte ADDR_ZEN = 0x05;

	// base32
	public static final short WS_OFFSET_CHECKSUM = 0;
	public static final short WS_OFFSET_TOP_BITS = 5;
	public static final short WS_OFFSET_BIG_VALUE = 10;
	public static final short WS_OFFSET_TEMP = 15;

	// // erc20
	// public static final short ERC_LENGTH = 29;// 1+1+7+20
	// public static final short ERC_OFFSET_DECIMAL = 0;
	// public static final short ERC_LEN_DECIMAL = 1;
	// public static final short ERC_OFFSET_NAME_LEN = 1;
	// public static final short ERC_OFFSET_NAME = 2;
	// public static final short ERC_LEN_NAME = 8;
	// public static final short ERC_OFFSET_ADDR = 9;
	// public static final short ERC_LEN_ADDR = 20;

	// bip32
	public static final short WORK_PRIKEY_OFFSET = 0;
	public static final short WORK_PUBKEY_OFFSET = 32;
	public static final short WORK_INDEX_OFFSET = 97;
	public static final short WORK_MESSAGE_OFFSET = 101;
	public static final short LENGTH_INDEX = 4;
	public static final short LENGTH_MESSAGE = 37;

	public static final short INT_LENGTH = 4;

	public static byte booleanToByte(boolean input) {
		return (byte) (input ? 1 : 0);
	}

	public static boolean byteToBoolean(byte input) {
		return input == 0 ? false : true;
	}

	public static void clearArray(byte[] buf) {
		Util.arrayFillNonAtomic(buf, Common.OFFSET_ZERO, (short) buf.length,
				(byte) 0);
	}

	public static void clearArray(boolean[] buf) {
		short size = (short) buf.length;
		for (short i = 0; i < size; i++) {
			buf[(short) (i)] = false;
		}
	}

	public static void clearArray(short[] buf) {
		short size = (short) buf.length;
		for (short i = 0; i < size; i++) {
			buf[(short) (i)] = 0;
		}
	}

}
