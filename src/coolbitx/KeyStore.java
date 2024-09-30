package coolbitx;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class KeyStore {
	public static final byte KEY_SE_ENC = 0;
	public static final byte KEY_SE_TRANS = 1;
	public static final byte KEY_SE_BACKUP = 2;

	private static final byte KEY_LENGTH = 64;

	public static ECPrivateKey getPrivKey(byte index) {
		switch (index) {
		case KEY_SE_ENC:
			return KeyUtil.getPrivKey(SEEncKey, Common.OFFSET_ZERO);
		case KEY_SE_TRANS:
			return KeyUtil.getPrivKey(SETransKey, Common.OFFSET_ZERO);
		case KEY_SE_BACKUP:
			return KeyUtil.getPrivKey(SEBackupKey, Common.OFFSET_ZERO);
		}
		return null;
	}

	public static AESKey getAESKey(byte index) {
		switch (index) {
		case KEY_SE_ENC:
			return KeyUtil.getAesKey(SEEncKey, Common.OFFSET_ZERO);
		case KEY_SE_TRANS:
			return KeyUtil.getAesKey(SETransKey, Common.OFFSET_ZERO);
		}
		return null;
	}

	public static void derive(byte cardType) {
		KeyGenerate.derive(cardType, KEY_SE_ENC, SEEncKey, Common.OFFSET_ZERO);
		KeyGenerate.derive(cardType, KEY_SE_TRANS, SETransKey,
				Common.OFFSET_ZERO);
	}

	public static void setKey(byte type, byte[] key, short keyOffset) {
		switch (type) {
		case KEY_SE_ENC:
			Util.arrayCopyNonAtomic(key, keyOffset, SEEncKey, (short) 0,
					KEY_LENGTH);
		case KEY_SE_TRANS:
			Util.arrayCopyNonAtomic(key, keyOffset, SETransKey, (short) 0,
					KEY_LENGTH);
		case KEY_SE_BACKUP:
			Util.arrayCopyNonAtomic(key, keyOffset, SEBackupKey, (short) 0,
					KEY_LENGTH);
		}

	}

	private static final byte[] SEEncKey = new byte[KEY_LENGTH];
	private static final byte[] SETransKey = new byte[KEY_LENGTH];
	private static final byte[] SEBackupKey = new byte[KEY_LENGTH];

	public static final byte[] SEBackupPubKey = { (byte) 0x04, (byte) 0x2e,
			(byte) 0x37, (byte) 0x02, (byte) 0x37, (byte) 0x05, (byte) 0x12,
			(byte) 0x59, (byte) 0xf6, (byte) 0xc4, (byte) 0x07, (byte) 0xfe,
			(byte) 0xf9, (byte) 0x20, (byte) 0x44, (byte) 0x64, (byte) 0x55,
			(byte) 0x7d, (byte) 0xba, (byte) 0x3c, (byte) 0xa0, (byte) 0x69,
			(byte) 0x4e, (byte) 0x06, (byte) 0x5f, (byte) 0xf0, (byte) 0x88,
			(byte) 0x48, (byte) 0xbc, (byte) 0x79, (byte) 0x76, (byte) 0xbe,
			(byte) 0xeb, (byte) 0x33, (byte) 0x91, (byte) 0xc8, (byte) 0x26,
			(byte) 0x48, (byte) 0x1e, (byte) 0x4b, (byte) 0x9c, (byte) 0x5d,
			(byte) 0x0c, (byte) 0x12, (byte) 0xb8, (byte) 0x5f, (byte) 0x70,
			(byte) 0x59, (byte) 0xc2, (byte) 0x1f, (byte) 0x20, (byte) 0x69,
			(byte) 0xdf, (byte) 0x77, (byte) 0xb0, (byte) 0xb5, (byte) 0x5c,
			(byte) 0x86, (byte) 0x2d, (byte) 0x92, (byte) 0xa3, (byte) 0x41,
			(byte) 0xc6, (byte) 0x24, (byte) 0xd2 };

	public static final byte[] SEBackupChainCode = { (byte) 0x6f, (byte) 0x7e,
			(byte) 0x87, (byte) 0xdf, (byte) 0x27, (byte) 0x8f, (byte) 0xb1,
			(byte) 0xe4, (byte) 0xd9, (byte) 0x82, (byte) 0x87, (byte) 0x11,
			(byte) 0xa5, (byte) 0xce, (byte) 0x56, (byte) 0xa8, (byte) 0xfe,
			(byte) 0xce, (byte) 0xfa, (byte) 0x1f, (byte) 0x86, (byte) 0x95,
			(byte) 0xf4, (byte) 0x10, (byte) 0x78, (byte) 0x6d, (byte) 0x43,
			(byte) 0x4e, (byte) 0x31, (byte) 0xcf, (byte) 0x70, (byte) 0xee };

	public static final byte[] CBPubKey = { (byte) 0x04, (byte) 0x04,
			(byte) 0x73, (byte) 0xf7, (byte) 0x20, (byte) 0x19, (byte) 0x54,
			(byte) 0x31, (byte) 0x13, (byte) 0x3f, (byte) 0xb5, (byte) 0x43,
			(byte) 0x38, (byte) 0x50, (byte) 0x85, (byte) 0xee, (byte) 0xaa,
			(byte) 0x87, (byte) 0x2a, (byte) 0x42, (byte) 0xe2, (byte) 0x94,
			(byte) 0xe6, (byte) 0x58, (byte) 0xa5, (byte) 0x1a, (byte) 0x58,
			(byte) 0x4e, (byte) 0xee, (byte) 0xf6, (byte) 0xc5, (byte) 0x35,
			(byte) 0x00, (byte) 0x65, (byte) 0x79, (byte) 0x1e, (byte) 0x38,
			(byte) 0x2f, (byte) 0x7f, (byte) 0xf5, (byte) 0xb5, (byte) 0xeb,
			(byte) 0x02, (byte) 0xaa, (byte) 0xe5, (byte) 0xd2, (byte) 0x7f,
			(byte) 0x74, (byte) 0xd0, (byte) 0xbe, (byte) 0x1d, (byte) 0xf1,
			(byte) 0x4e, (byte) 0xbf, (byte) 0x3f, (byte) 0x94, (byte) 0x4b,
			(byte) 0xd4, (byte) 0x0e, (byte) 0x09, (byte) 0x88, (byte) 0x4d,
			(byte) 0xa6, (byte) 0x41, (byte) 0xca };

	public static final byte[] ScriptPubKey = { (byte) 0x04, (byte) 0xb0,
			(byte) 0x19, (byte) 0x0e, (byte) 0xd0, (byte) 0x59, (byte) 0xa2,
			(byte) 0xc5, (byte) 0x27, (byte) 0x6f, (byte) 0x53, (byte) 0xfe,
			(byte) 0x08, (byte) 0xb1, (byte) 0xb2, (byte) 0x2c, (byte) 0x41,
			(byte) 0x39, (byte) 0x1d, (byte) 0x87, (byte) 0x11, (byte) 0x01,
			(byte) 0x6e, (byte) 0xc0, (byte) 0xf7, (byte) 0x06, (byte) 0x91,
			(byte) 0xb7, (byte) 0x18, (byte) 0xc7, (byte) 0x6b, (byte) 0xa9,
			(byte) 0x94, (byte) 0x8d, (byte) 0x48, (byte) 0xfe, (byte) 0xb5,
			(byte) 0xa1, (byte) 0x8a, (byte) 0x6b, (byte) 0x78, (byte) 0x7b,
			(byte) 0x0d, (byte) 0x6d, (byte) 0x6f, (byte) 0xcd, (byte) 0xfe,
			(byte) 0x92, (byte) 0x59, (byte) 0x17, (byte) 0xd2, (byte) 0xb4,
			(byte) 0xc0, (byte) 0x8b, (byte) 0xd4, (byte) 0xe6, (byte) 0x18,
			(byte) 0x3c, (byte) 0x43, (byte) 0xa7, (byte) 0x5a, (byte) 0x56,
			(byte) 0x96, (byte) 0xe2, (byte) 0x02 };

}
