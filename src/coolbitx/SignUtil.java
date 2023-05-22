package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Signature;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class SignUtil {
	private static Signature verifySignature;

	public static void init() {
		verifySignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256,
				false);
	}

	public static void uninit() {
		verifySignature = null;
	}

	public static short sign(byte[] buf, short offset, short signLength,
			ECPrivateKey privateKey, byte[] destBuf, short destOff) {
		return Secp256k1.signRFC6979(destBuf, destOff, buf, offset, signLength, privateKey);
	}

	private static boolean verify(byte[] buf, short offset, short length,
			byte[] signBuf, short signOff, short signLen, ECPublicKey publicKey) {
		FlowCounter.increase(); // ++
		verifySignature.init(publicKey, Signature.MODE_VERIFY);
		FlowCounter.increase(); // ++
		return verifySignature.verifyPreComputedHash(buf, offset, length,
				signBuf, signOff, signLen);
	}

	public static boolean isVerifiedFixedLength(byte[] dataBuf,
			short dataOffset, short dataLength, byte[] signBuf,
			short signOffset, ECPublicKey publicKey) {
		// signBuf=[zeroes(Variety)][realSignature(Variety)], total 72B
		// Verify sign with SHA256(data) and publicKey
		// return success or not

		if (Main.developMode && (signBuf[signOffset] & 0x00FF) == 0x00FA) {
			// WildCard signature FA0000...00 only for factoryMode
			return true;
		}

		short signLength = 72;
		while (signBuf[signOffset] == 0 && signLength > 65) {
			signOffset++;
			signLength--;
		}
		short workLength = 32;
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK1);
		short workspaceOffset = WorkCenter.getWorkspaceOffset(workLength);
		ShaUtil.SHA256(dataBuf, dataOffset, dataLength, workspace,
				workspaceOffset);
		boolean ret = verify(workspace, workspaceOffset, (short) 32, signBuf,
				signOffset, signLength, publicKey);
		WorkCenter.release(WorkCenter.WORK1, workLength);
		return ret;
	}

	public static void verifyData(byte[] buf, short dataOffset,
			short dataLength, byte[] signBuf, short signOffset,
			short signLength, ECPublicKey publicKey) {
		boolean result = verify(buf, dataOffset, dataLength, signBuf,
				signOffset, signLength, publicKey);
		if (!result) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

//	public static void verifyCmdWithOutData(byte[] buf, boolean haveNonce,
//			short signOffset, short signLength, ECPublicKey publicKey) {
//		verifyCmd(buf, (short) 0, (short) 0, haveNonce, signOffset, signLength,
//				publicKey);
//	}
//
//	public static void verifyCmd(byte[] buf, short dataOffset,
//			short dataLength, boolean haveNonce, short signOffset,
//			short signLen, ECPublicKey publicKey) {
//		FlowCounter.increase(); // ++
//		if (haveNonce && !CardInfo.is(CardInfo.NONCE_ACTI)) {
//			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//		}
//		FlowCounter.increase(); // ++
//		// Cmd
//		ShaUtil.m_sha_256.update(buf, Common.OFFSET_ZERO, (short) 4);
//		// Data
//		if ((dataOffset != 0) && (dataLength != 0)) {
//			ShaUtil.m_sha_256.update(buf, dataOffset, dataLength);
//		}
//		// Nonce
//		if (haveNonce) {
//			ShaUtil.m_sha_256.update(Main.nonce, Common.OFFSET_ZERO,
//					Common.LENGTH_NONCE);
//			CardInfo.set(CardInfo.NONCE_ACTI, false);
//		}
//		FlowCounter.increase(); // ++
//		// hash
//		ShaUtil.m_sha_256.doFinal(buf, dataOffset, (short) 0,
//				Main.workspace, Common.OFFSET_ZERO);
//		FlowCounter.increase(); // ++
//		boolean result = verify(Main.workspace, Common.OFFSET_ZERO,
//				Common.LENGTH_SHA256, buf, signOffset, signLen, publicKey);
//		FlowCounter.increase(); // ++
//		if (!result) {
//			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
//		}
//		FlowCounter.increase(); // ++
//	}
}
