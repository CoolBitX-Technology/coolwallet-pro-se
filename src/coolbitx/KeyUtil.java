package coolbitx;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class KeyUtil {
	private static KeyAgreement ka;
	private static ECPrivateKey privateKey;
	private static ECPublicKey publicKey;
	private static AESKey aesKey;

	public static void init() {
		ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY,
				false);
		privateKey = (ECPrivateKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256,
				false);
		Secp256k1.setCommonCurveParameters(privateKey);
		publicKey = (ECPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256,
				false);
		Secp256k1.setCommonCurveParameters(publicKey);
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
				KeyBuilder.LENGTH_AES_256, false);
	}

	public static void uninit() {
		ka = null;
		privateKey = null;
		publicKey = null;
		aesKey = null;
	}

	public static short sharedSecret(ECPrivateKey privateKey, byte[] buf,
			short offset, byte[] destBuf, short destOff) {
		ka.init(privateKey);
		short length = ka.generateSecret(buf, offset, Common.LENGTH_PUBLICKEY,
				destBuf, destOff);
		return length;// 65byte 04...
	}

	public static short privToPubKey(byte[] key, short keyOffset,
			byte[] destBuf, short destOff) {
		byte[] tempKey = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short tempKeyOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_PUBLICKEY);
		ka.init(getPrivKey(key, keyOffset));
		ka.generateSecret(Secp256k1.G, Common.OFFSET_ZERO,
				Common.LENGTH_PUBLICKEY, tempKey, tempKeyOffset);
		compressPublicKey(tempKey, tempKeyOffset);
		Util.arrayCopyNonAtomic(tempKey, tempKeyOffset, destBuf, destOff,
				Common.LENGTH_COMPRESS_PUBLICKEY);
		WorkCenter.release(WorkCenter.WORK, Common.LENGTH_PUBLICKEY);
		return Common.LENGTH_COMPRESS_PUBLICKEY;
	}

	public static ECPrivateKey getPrivKey(byte[] keyBuf, short keyOffset) {
		privateKey.setS(keyBuf, keyOffset, Common.LENGTH_PRIVATEKEY);
		return privateKey;
	}

	public static ECPublicKey getPubKey(byte[] pubKey, short keyOffset) {
		publicKey.setW(pubKey, keyOffset, Common.LENGTH_PUBLICKEY);
		return publicKey;
	}

	public static AESKey getAesKey(byte[] key, short offset) {
		aesKey.setKey(key, offset);
		return aesKey;
	}

	private static void compressPublicKey(byte[] buffer, short offset) {
		buffer[(short) (offset)] = ((buffer[(short) ((short) (offset + 64))] & 1) != 0 ? (byte) 0x03
				: (byte) 0x02);
	}
}
