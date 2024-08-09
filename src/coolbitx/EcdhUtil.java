package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class EcdhUtil {
	private static Cipher cipher;
	private static KeyPair ephemkeyPair;
	private static ECPublicKey ephemPublicKey;

	public static void init() {
		cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
		ephemkeyPair = Secp256k1.newKeyPair();
	}

	public static void uninit() {
		cipher = null;
		ephemkeyPair = null;
		ephemPublicKey = null;
	}

	public static short decryptAES(byte[] cipherBuf, short cipherOffset,
			short cipherLength, byte[] destBuf, short destOffset, AESKey key) {
		short resultLength = 0;
		try {
			cipher.init(key, Cipher.MODE_DECRYPT);
			resultLength = cipher.doFinal(cipherBuf, cipherOffset,
					cipherLength, destBuf, destOffset);
		} catch (CryptoException e) {
			ISOException.throwIt((short) 0x6BAC);
		}
		return resultLength;
	}

	public static short decrypt(byte[] buf, short offset, short length,
			byte[] destBuf, short destOff, ECPrivateKey privKey) {
		// buf: ephemeral public key(65bytes)||MAC(20bytes)||encryptData
		short encryptDataOff = (short) (offset + Common.LENGTH_PUBLICKEY + Common.LENGTH_MAC);
		short encryptDataLength = (short) (length - Common.LENGTH_PUBLICKEY - Common.LENGTH_MAC);

		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workspaceOffset = WorkCenter.getWorkspaceOffset((short) 65);
		// Create shared secret and store in workspace
		KeyUtil.sharedSecret(privKey, buf, offset, workspace, workspaceOffset);

		// Key derivation function
		// store final key(enc key||mac key) in workspace
		ShaUtil.SHA512(workspace, (short) (workspaceOffset + 1), (short) 32,
				workspace, workspaceOffset);
		// take the first half of fianl key as cipher key
		cipher.init(KeyUtil.getAesKey(workspace, workspaceOffset),
				Cipher.MODE_DECRYPT);

		// Calculate MAC
		byte[] macData = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short macDataOffset = WorkCenter
				.getWorkspaceOffset((short) (Common.LENGTH_IV
						+ Common.LENGTH_PUBLICKEY + encryptDataLength));
		short p = macDataOffset;
		p += Common.LENGTH_IV;
		p = Util.arrayCopyNonAtomic(buf, offset, macData, p,
				Common.LENGTH_PUBLICKEY);
		p = Util.arrayCopyNonAtomic(buf, encryptDataOff, macData, p,
				encryptDataLength);
		// take the second half of fianl key as mac key
		// store MAC after final key in workspace
		short macLength = HmacSha.HMAC(workspace,
				(short) (workspaceOffset + 32), (short) 32, macData,
				macDataOffset, (short) (p - macDataOffset), workspace,
				workspaceOffset, ShaUtil.m_sha_1);
		WorkCenter.release(WorkCenter.WORK, (short) (Common.LENGTH_IV
				+ Common.LENGTH_PUBLICKEY + encryptDataLength));

		// Compare MAC
		short compare = Util.arrayCompare(buf,
				(short) (offset + Common.LENGTH_PUBLICKEY), workspace,
				workspaceOffset, macLength);
		if (compare != 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		WorkCenter.release(WorkCenter.WORK, (short) 65);
		return cipher.doFinal(buf, encryptDataOff, encryptDataLength, destBuf,
				destOff);
	}

	public static short encryptAES(byte[] plainBuf, short plainOffset,
			short plainLength, byte[] destBuf, short destOffset, AESKey key) {
		cipher.init(key, Cipher.MODE_ENCRYPT);
		return cipher.doFinal(plainBuf, plainOffset, plainLength, destBuf,
				destOffset);

	}

	public static short encrypt(byte[] buf, short offset, short length,
			byte[] destBuf, short destOff) {
		// ==== 1st get workspace ====
		byte[] inBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short inBufOffset = WorkCenter.getWorkspaceOffset(length);
		Util.arrayCopyNonAtomic(buf, offset, inBuf, inBufOffset, length);
		// create ephem keyPair
		ephemkeyPair.genKeyPair();
		ephemPublicKey = (ECPublicKey) ephemkeyPair.getPublic();
		short ephemPublicKeyLength = ephemPublicKey.getW(destBuf, destOff);
		short MacOff = (short) (destOff + ephemPublicKeyLength);

		// Create shared secret
		// ==== 2nd get workspace ====
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workspaceOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_PUBLICKEY);
		// ==== 3rd get workspace ====
		byte[] appPublicKey = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short appPublicKeyOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_PUBLICKEY);
		Device.getAppPublicKeyAsByteArray(appPublicKey, appPublicKeyOffset);
		KeyUtil.sharedSecret((ECPrivateKey) ephemkeyPair.getPrivate(),
				appPublicKey, appPublicKeyOffset, workspace, workspaceOffset);
		// ==== release 3rd workspace ====
		WorkCenter.release(WorkCenter.WORK, Common.LENGTH_PUBLICKEY);

		// Derivation final key(enc key||mac key) in workspace
		short keyLength = ShaUtil.SHA512(workspace,
				(short) (workspaceOffset + 1), (short) 32, workspace,
				workspaceOffset);
		// encrypt data
		short encryptDataOff = (short) (MacOff + Common.LENGTH_MAC);
		// take the first half of fianl key as cipher key
		cipher.init(KeyUtil.getAesKey(workspace, workspaceOffset),
				Cipher.MODE_ENCRYPT);
		// short updateLength = cipher.update(inBuf, inBufOffset, length,
		// destBuf,
		// encryptDataOff);
		short encryptLength = cipher.doFinal(inBuf, inBufOffset, length,
				destBuf, encryptDataOff);

		// Calculate MAC
		// short macDataLength = Common.OFFSET_ZERO;
		// ==== 4th get workspace ====
		byte[] macData = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short macDataOffset = WorkCenter
				.getWorkspaceOffset((short) (16 + 65 + encryptLength));
		short p = macDataOffset;
		p += Common.LENGTH_IV;
		p = Util.arrayCopyNonAtomic(destBuf, destOff, macData, p,
				Common.LENGTH_PUBLICKEY);
		p = Util.arrayCopyNonAtomic(destBuf, encryptDataOff, macData, p,
				encryptLength);
		// take the second half of fianl key as mac key
		// store MAC after final key in destBuff
		short macLength = HmacSha.HMAC(workspace,
				(short) (workspaceOffset + (keyLength / 2)),
				(short) (keyLength / 2), macData, macDataOffset,
				(short) (p - macDataOffset), destBuf, MacOff, ShaUtil.m_sha_1);
		// ==== release 4th workspace ====
		WorkCenter.release(WorkCenter.WORK, (short) (16 + 65 + encryptLength));
		// ==== release 2nd workspace ====
		WorkCenter.release(WorkCenter.WORK, Common.LENGTH_PUBLICKEY);
		// ==== release 1st workspace ====
		WorkCenter.release(WorkCenter.WORK1, length);

		return (short) (ephemPublicKeyLength + macLength + encryptLength);
	}
}
