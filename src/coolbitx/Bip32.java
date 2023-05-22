package coolbitx;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Bip32 {
	// private key(32b) + chain code(32b)
	public static final short LENGTH_EXTENDKEY = 64;

	public static final byte[] standardPath = { 0x32, (byte) 0x80, 0x00, 0x00,
			0x2C, (byte) 0x80, 0x00, 0x00, 0x00, (byte) 0x80, 0x00, 0x00, 0x00,
			(byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00 };

	private static final byte[] masterSecretKey = { 'B', 'i', 't', 'c', 'o',
			'i', 'n', ' ', 's', 'e', 'e', 'd' };

	private static final byte[] masterSecretKeyEd25519 = { 'e', 'd', '2', '5',
			'5', '1', '9', ' ', 's', 'e', 'e', 'd' };

	private static RSAPrivateKey seedObject;

	public static void init() {
		seedObject = (RSAPrivateKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
	}

	public static void uninit() {
		seedObject = null;
	}

	public static void clearKey() {
		seedObject.clearKey();
	}

	public static void setSeed(byte[] seed, short seedOffset, short length) {
		clearKey();
		seedObject.setExponent(seed, seedOffset, length);
	}

	public static void getAccountDigest(byte[] destBuf, short destOffset,
			short count) {
		final short workspaceLength = 84;
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short workspaceOffset = WorkCenter.getWorkspaceOffset(workspaceLength);
		getDerivedKeyByPath(standardPath, (short) 0, (short) 1, workspace,
				workspaceOffset);
		ShaUtil.SHA1(workspace, workspaceOffset, LENGTH_EXTENDKEY, workspace,
				(short) (workspaceOffset + 64));
		Util.arrayFillNonAtomic(workspace, workspaceOffset, (short) 64,
				(byte) 0);
		Util.arrayCopyNonAtomic(workspace, (short) (workspaceOffset + 64),
				destBuf, destOffset, count);
		Util.arrayFillNonAtomic(workspace, workspaceOffset, (short) 84,
				(byte) 0);
		WorkCenter.release(WorkCenter.WORK1, workspaceLength);
	}

	public static short backupData(byte[] destBuf, short destOffset) {
		seedObject.getExponent(destBuf, destOffset);
		return LENGTH_EXTENDKEY;
	}

	public static short recoverData(byte[] buf, short offset) {
		seedObject.setExponent(buf, offset, LENGTH_EXTENDKEY);
		offset += LENGTH_EXTENDKEY;
		return offset;
	}

	public static void deriveChildKey(byte[] buf, short offset, byte[] index,
			short indexOffset, boolean isEd25519, byte[] destBuf,
			short destOffset) {
		if ((index[indexOffset] & (byte) 0x80) != 0) {
			// put 00 || private key
			Main.workspace[(short) (0)] = (byte) 0x00;
			Util.arrayCopyNonAtomic(buf, offset, Main.workspace,
					Common.OFFSET_ONE, Common.LENGTH_PRIVATEKEY);
		} else {
			if (isEd25519) {
				ISOException.throwIt((short) 0x6D6C);
			}
			// put compress public key
			KeyUtil.privToPubKey(buf, offset, Main.workspace,
					Common.OFFSET_ZERO);
		}
		Util.arrayCopyNonAtomic(index, indexOffset, Main.workspace,
				(short) (33), (short) 4);
		byte[] trans = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short transOffset = WorkCenter.getWorkspaceOffset(LENGTH_EXTENDKEY);
		HmacSha.HMAC(buf, (short) (offset + Common.LENGTH_PRIVATEKEY),
				Common.LENGTH_CHAINCODE, Main.workspace, Common.OFFSET_ZERO,
				Common.LENGTH_MESSAGE, trans, transOffset, ShaUtil.m_sha_512);
		if (!isEd25519) {
			MathUtil.addm(buf, offset, (short) 32, trans, transOffset, trans,
					transOffset, Secp256k1.R, Common.OFFSET_ZERO);
		}
		Util.arrayCopy(trans, transOffset, destBuf, destOffset,
				LENGTH_EXTENDKEY);
		WorkCenter.release(WorkCenter.WORK1, LENGTH_EXTENDKEY);
	}

	private static void getDerivedKeyByPath(byte[] path, short pathOffset,
			short pathLength, byte[] destBuf, short destOffset) {
		if (pathLength < 1 || (short) (pathLength - 1) % 4 != 0
				|| pathLength > 21) {
			ISOException.throwIt((short) 0x6D63);
		}
		byte[] seed = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short seedOffset = WorkCenter.getWorkspaceOffset(Common.LENGTH_SEED);
		seedObject.getExponent(seed, seedOffset);
		byte keyType = path[pathOffset];
		switch (keyType) {
		case KeyManager.BIP32:
		case KeyManager.BIP32EDDSA:
			HmacSha.HMAC(masterSecretKey, Common.OFFSET_ZERO,
					(short) masterSecretKey.length, seed, seedOffset,
					(short) 64, destBuf, destOffset, ShaUtil.m_sha_512);
			break;
		case KeyManager.SLIP0010:
			HmacSha.HMAC(masterSecretKeyEd25519, Common.OFFSET_ZERO,
					(short) masterSecretKeyEd25519.length, seed, seedOffset,
					(short) 64, destBuf, destOffset, ShaUtil.m_sha_512);
			break;
		default:
			ISOException.throwIt((short) 0x6D65);
		}
		for (byte derivedPathLength = 1; derivedPathLength < pathLength; derivedPathLength += 4) {
			deriveChildKey(destBuf, destOffset, path,
					(short) (pathOffset + derivedPathLength),
					path[pathOffset] == 0x10, destBuf, destOffset);
		}
		WorkCenter.release(WorkCenter.WORK1, Common.LENGTH_SEED);
	}

	public static short getDerivedPublicKey(byte[] path, short pathOffset,
			short pathLength, boolean needChainCode, byte[] destBuf,
			short destOffset) {
		final short transLength = 64;
		byte[] trans = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short transOffset = WorkCenter.getWorkspaceOffset(transLength);
		short ret = 0;
		byte keyType = path[pathOffset];

		if (keyType != KeyManager.CURVE25519)
			getDerivedKeyByPath(path, pathOffset, pathLength, trans,
					transOffset);
		switch (keyType) {
		case KeyManager.BIP32: // ECDSA secp256k1
			KeyUtil.privToPubKey(trans, transOffset, destBuf, destOffset);
			ret = 33;
			if (needChainCode) {
				Util.arrayCopyNonAtomic(trans, (short) (transOffset + 32),
						destBuf, (short) (destOffset + 33), (short) 32);
				ret += 32;
			}
			break;
		case KeyManager.SLIP0010: // EdDSA Ed25519
		case KeyManager.BIP32EDDSA:
			Ed25519.getPublic(destBuf, destOffset, trans, transOffset);
			ret = 32;
			break;
		case KeyManager.CURVE25519:
			seedObject.getExponent(trans, transOffset);
			Ed25519.getCurve25519PublicKey(trans, transOffset, destBuf,
					destOffset);
			ret = 32;
			break;
		default:
			ISOException.throwIt((short) 0x6AC4);
			break;
		}

		WorkCenter.release(WorkCenter.WORK1, transLength);
		return ret;
	}

	public static short signByDerivedKey(byte[] buf, short offset,
			short length, byte[] path, short pathOffset, short pathLength,
			byte signType, byte[] destBuf, short destOffset) {
		byte[] trans = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short transOffset = WorkCenter.getWorkspaceOffset(LENGTH_EXTENDKEY);

		if (signType != KeyManager.SIGN_CURVE25519)
			getDerivedKeyByPath(path, pathOffset, pathLength, trans,
					transOffset);
		short ret;
		switch (signType) {
		case KeyManager.SIGN_SECP256K1: // ECDSA secp256k1
			ret = SignUtil
					.sign(buf, offset, length,
							KeyUtil.getPrivKey(trans, transOffset), destBuf,
							destOffset);
			break;
		case KeyManager.SIGN_ED25519: // EdDSA Ed25519
			Ed25519.sign(destBuf, destOffset, buf, offset, length, trans,
					transOffset);
			ret = 64;
			break;
		case KeyManager.SIGN_CURVE25519: // Curve25519
			// Generate random bytes to signing curve25519
			byte[] rnd = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
			short rndOffset = WorkCenter
					.getWorkspaceOffset(Common.LENGTH_SHA512);
			NonceUtil.randomNonce(rnd, rndOffset, Common.LENGTH_SHA512);
			seedObject.getExponent(trans, transOffset);
			Ed25519.signCurve25519Random(destBuf, destOffset, buf, offset,
					length, rnd, rndOffset, trans, transOffset);
			WorkCenter.release(WorkCenter.WORK1, Common.LENGTH_SHA512);
			ret = 64;
			break;
		default:
			ISOException.throwIt((short) 0x6AC3);
			ret = 0;
			break;
		}

		WorkCenter.release(WorkCenter.WORK1, LENGTH_EXTENDKEY);
		return ret;
	}
}
