package coolbitx;

import com.nxp.id.jcopx.math.Math;

import coolbitx.Common;
import javacard.framework.Util;

public class Bip86 {

	public static void tweakKey(byte[] privateKey, short privateKeyOffset) {
		modifyPrivateKey(privateKey, privateKeyOffset);
		byte[] publicKey = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short publicKeyOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_COMPRESS_PUBLICKEY);
		KeyUtil.privToPubKey(privateKey, privateKeyOffset, publicKey,
				publicKeyOffset);
		byte[] tweak = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short tweakOffset = WorkCenter.getWorkspaceOffset(Common.LENGTH_SHA256);
		Bip340.taggedHash(Bip340.TapTweak, publicKey,
				(short) (publicKeyOffset + 1), (short) 32, tweak, tweakOffset,
				ShaUtil.m_sha_256);
		// A = A + B mod N
		// modularAdd(byte[] A, byte[] N);
		Math.modularAdd(privateKey, privateKeyOffset, (short) 32, tweak,
				tweakOffset, (short) 32, Secp256k1.R, Common.OFFSET_ZERO,
				(short) 32);
		WorkCenter
				.release(
						WorkCenter.WORK1,
						(short) (Common.LENGTH_COMPRESS_PUBLICKEY + Common.LENGTH_SHA256));
	}

	public static void modifyPrivateKey(byte[] privateKey,
			short privateKeyOffset) {
		byte[] publicKey = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short publicKeyOffset = WorkCenter
				.getWorkspaceOffset(Common.LENGTH_COMPRESS_PUBLICKEY);
		KeyUtil.privToPubKey(privateKey, privateKeyOffset, publicKey,
				publicKeyOffset);
		if (publicKey[publicKeyOffset] != (byte) 0x02) { // equals to 0x03
			byte[] newPrivateKey = WorkCenter
					.getWorkspaceArray(WorkCenter.WORK1);
			short newPrivateKeyOffset = WorkCenter
					.getWorkspaceOffset(Common.LENGTH_PRIVATEKEY);
			Util.arrayCopyNonAtomic(Secp256k1.R, Common.OFFSET_ZERO,
					newPrivateKey, newPrivateKeyOffset,
					Common.LENGTH_PRIVATEKEY);
			// A = A - B mod N
			// modularSubtract(byte[] A, byte[] B, byte[] N);
			Math.modularSubtract(newPrivateKey, newPrivateKeyOffset,
					Common.LENGTH_PRIVATEKEY, privateKey, privateKeyOffset,
					Common.LENGTH_PRIVATEKEY, Secp256k1.R, Common.OFFSET_ZERO,
					Common.LENGTH_PRIVATEKEY);

			Util.arrayCopyNonAtomic(newPrivateKey, newPrivateKeyOffset,
					privateKey, privateKeyOffset, Common.LENGTH_PRIVATEKEY);
			WorkCenter.release(WorkCenter.WORK1, Common.LENGTH_PRIVATEKEY);
		}
		WorkCenter.release(WorkCenter.WORK1, Common.LENGTH_COMPRESS_PUBLICKEY);
	}
}
