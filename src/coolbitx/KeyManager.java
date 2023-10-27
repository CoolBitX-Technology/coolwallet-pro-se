package coolbitx;

import javacard.framework.ISOException;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class KeyManager {
	public static final byte BIP32 = 0x32;
	public static final byte SLIP0010 = 0x10;
	public static final byte BIP32EDDSA = 0x42;
	public static final byte BIP32ED25519 = 0x17;
	public static final byte CURVE25519 = 0x19;
	public static final byte BIP340 = 0x34;

	public static final byte SIGN_SECP256K1 = 0x01;
	public static final byte SIGN_ED25519 = 0x02;
	public static final byte SIGN_BIP32ED25519 = 0x03;
	public static final byte SIGN_CURVE25519 = 0x04;
	public static final byte SIGN_SCHNORR = 0x05;

	public static void init() {
		Bip32.init();
		Secp256k1.init();
		HmacDrbg.init();
		Ed25519.init();
		Bip32Ed25519.init();
	}

	public static void uninit() {
		Bip32.uninit();
		Secp256k1.uninit();
		HmacDrbg.uninit();
		Ed25519.uninit();
		Bip32Ed25519.uninit();
	}

	public static void clearKey() {
		Bip32.clearKey();
		Bip32Ed25519.clearKey();
	}

	public static void setSeed(byte[] buf, short offset, short length) {
		Bip32.setSeed(buf, offset, Common.LENGTH_SEED);
		if (length > Common.LENGTH_SEED) {
			Bip32Ed25519.setMasterKey(buf,
					(short) (offset + Common.LENGTH_SEED),
					Common.LENGTH_BIP32ED25519KEY);
		}
	}

	public static short getDerivedPublicKey(byte[] path, short pathOffset,
			short pathLength, boolean needChainCode, byte[] destBuf,
			short destOffset) {
		short ret = 0;

		byte keyType = path[pathOffset];
		switch (keyType) {
		case BIP32: // ECDSA secp256k1
		case SLIP0010: // EdDSA Ed25519
		case CURVE25519:
		case BIP32EDDSA:
			ret = Bip32.getDerivedPublicKey(path, pathOffset, pathLength,
					needChainCode, destBuf, destOffset);
			break;
		case BIP32ED25519:
			ret = Bip32Ed25519.getDerivedPublicKey(path, pathOffset,
					pathLength, needChainCode, destBuf, destOffset);
			break;
		default:
			ISOException.throwIt((short) 0x6AC3);
			break;
		}
		return ret;
	}

	public static short signByDerivedKey(byte[] buf, short offset,
			short length, byte[] path, short pathOffset, short pathLength,
			byte signType, byte[] destBuf, short destOffset) {
		short ret;
		switch (signType) {
		case SIGN_SECP256K1: // ECDSA secp256k1
		case SIGN_ED25519: // EdDSA Ed25519
		case SIGN_CURVE25519:
		case SIGN_SCHNORR:
			ret = Bip32.signByDerivedKey(buf, offset, length, path, pathOffset,
					pathLength, signType, destBuf, destOffset);
			break;
		case SIGN_BIP32ED25519: // Bip32 Ed25519
			ret = Bip32Ed25519.signByDerivedKey(buf, offset, length, path,
					pathOffset, pathLength, signType, destBuf, destOffset);
			break;
		default:
			ISOException.throwIt((short) 0x6AC3);
			ret = 0;
			break;
		}

		return ret;
	}

}
