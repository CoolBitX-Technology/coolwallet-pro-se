package coolbitx.sio;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

public class GenuineKey implements GenuineKeyI {

	private static final byte[] installPublicKey = { (byte) 0x04, (byte) 0x01,
			(byte) 0xe3, (byte) 0xa7, (byte) 0xde, (byte) 0x77, (byte) 0x92,
			(byte) 0x76, (byte) 0xef, (byte) 0x24, (byte) 0xb9, (byte) 0xd5,
			(byte) 0x61, (byte) 0x7b, (byte) 0xa8, (byte) 0x6b, (byte) 0xa4,
			(byte) 0x6d, (byte) 0xc5, (byte) 0xa0, (byte) 0x10, (byte) 0xbe,
			(byte) 0x0c, (byte) 0xe7, (byte) 0xaa, (byte) 0xf6, (byte) 0x58,
			(byte) 0x76, (byte) 0x40, (byte) 0x2f, (byte) 0x6a, (byte) 0x53,
			(byte) 0xa5, (byte) 0xcf, (byte) 0x1f, (byte) 0xec, (byte) 0xab,
			(byte) 0x85, (byte) 0x70, (byte) 0x3d, (byte) 0xf9, (byte) 0x2e,
			(byte) 0x9c, (byte) 0x43, (byte) 0xe1, (byte) 0x2a, (byte) 0x49,
			(byte) 0xf3, (byte) 0x33, (byte) 0x70, (byte) 0x76, (byte) 0x11,
			(byte) 0x53, (byte) 0x21, (byte) 0x6d, (byte) 0xf8, (byte) 0x29,
			(byte) 0x1b, (byte) 0x7a, (byte) 0xa2, (byte) 0xf1, (byte) 0xa7,
			(byte) 0x75, (byte) 0xb0, (byte) 0x86 };

	public static final short SECRET_LENGTH = 1024;

	private Cipher cipher;
	private byte[] decryptBuf;
	private short decryptLength;

	private short installType = 0;
	private byte[] cardName;
	private short cardNameLength;
	private byte[] secret;
	private short secretLength;

	public GenuineKey() {
		cipher = null;
		decryptBuf = null;
		decryptLength = 0;

		installType = 0;
		cardName = new byte[32];
		cardNameLength = (short) 0;
		secret = new byte[SECRET_LENGTH];
		secretLength = (short) 0;
	}

	public short getPublicKey(byte[] destBuf, short destOffset) {
		KeyPair keyPair = Secp256k1.newKeyPair();
		keyPair.genKeyPair();
		short ret = ((ECPublicKey) keyPair.getPublic()).getW(destBuf,
				destOffset);

		KeyAgreement ka = KeyAgreement.getInstance(
				KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
		ka.init(keyPair.getPrivate());
		ka.generateSecret(installPublicKey, (short) 0, (short) 65, secret,
				(short) 0);
		secretLength = 0;

		AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
				KeyBuilder.LENGTH_AES_256, false);
		aesKey.setKey(secret, (short) 1);
		cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
		cipher.init(aesKey, Cipher.MODE_DECRYPT);
		decryptBuf = new byte[SECRET_LENGTH];
		decryptLength = 0;

		aesKey = null;
		keyPair = null;
		ka = null;
		JCSystem.requestObjectDeletion();

		return ret;

	}

	public void setSecretUpdate(byte[] cipherBuf, short cipherOffset,
			short cipherLength) {
		if (cipher == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		decryptLength = Util.arrayCopyNonAtomic(cipherBuf, cipherOffset,
				decryptBuf, decryptLength, cipherLength);
	}

	public void setSecretFinal() {
		if (cipher == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		decryptLength = cipher.doFinal(decryptBuf, (short) 0, decryptLength,
				decryptBuf, (short) 0);
		if (decryptLength < 32) {
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		}

		MessageDigest sha256 = MessageDigest.getInstance(
				MessageDigest.ALG_SHA_256, false);
		byte checksumBuf[] = JCSystem.makeTransientByteArray((short) 32,
				JCSystem.CLEAR_ON_DESELECT);
		sha256.doFinal(decryptBuf, (short) 32, (short) (decryptLength - 32),
				checksumBuf, (short) 0);
		if (Util.arrayCompare(decryptBuf, (short) 0, checksumBuf, (short) 0,
				(short) 32) != 0) {
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		}

		installType = decryptBuf[32];
		cardNameLength = decryptBuf[33];
		secretLength = (short) (decryptLength - 34 - cardNameLength);
		Util.arrayCopyNonAtomic(decryptBuf, (short) 34, cardName, (short) 0,
				cardNameLength);
		Util.arrayCopyNonAtomic(decryptBuf, (short) (34 + cardNameLength),
				secret, (short) 0, secretLength);

		cipher = null;
		decryptBuf = null;
		sha256 = null;
		checksumBuf = null;
		JCSystem.requestObjectDeletion();
	}

	public short getInstallType() {
		return installType;
	}

	public short getCardName(byte[] destBuf, short destOffset) {
		Util.arrayCopyNonAtomic(cardName, (short) 0, destBuf, destOffset,
				cardNameLength);
		return cardNameLength;
	}

	public short getGenuinePrivateKey(byte[] destBuf, short destOffset) {
		return getSecret((short) 0, (short) 32, destBuf, destOffset);
	}

	public short getGenuineChainCode(byte[] destBuf, short destOffset) {
		return getSecret((short) 32, (short) 32, destBuf, destOffset);
	}

	public short getSecret(short srcOffset, short length, byte[] destBuf,
			short destOffset) {
		if ((short) (srcOffset + length) > secretLength) {
			length = (short) (secretLength - srcOffset);
		}
		if (length <= 0) {
			return 0;
		}
		Util.arrayCopyNonAtomic(secret, srcOffset, destBuf, destOffset, length);
		return length;
	}

}
