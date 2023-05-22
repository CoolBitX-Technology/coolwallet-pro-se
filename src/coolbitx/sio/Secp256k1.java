package coolbitx.sio;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Secp256k1 {

	public final static byte[] FP = { // 32 bytes
	(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xff, (byte) 0xff,
			(byte) 0xfc, (byte) 0x2f };

	public final static byte[] A = { // 32 bytes
	(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00 };

	public final static byte[] B = { // 32 bytes
	(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x07 };

	public final static byte[] G = { // 65 bytes
	(byte) 0x04, (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e,
			(byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac, (byte) 0x55,
			(byte) 0xa0, (byte) 0x62, (byte) 0x95, (byte) 0xce, (byte) 0x87,
			(byte) 0x0b, (byte) 0x07, (byte) 0x02, (byte) 0x9b, (byte) 0xfc,
			(byte) 0xdb, (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9,
			(byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b, (byte) 0x16,
			(byte) 0xf8, (byte) 0x17, (byte) 0x98, (byte) 0x48, (byte) 0x3a,
			(byte) 0xda, (byte) 0x77, (byte) 0x26, (byte) 0xa3, (byte) 0xc4,
			(byte) 0x65, (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc,
			(byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8, (byte) 0xfd,
			(byte) 0x17, (byte) 0xb4, (byte) 0x48, (byte) 0xa6, (byte) 0x85,
			(byte) 0x54, (byte) 0x19, (byte) 0x9c, (byte) 0x47, (byte) 0xd0,
			(byte) 0x8f, (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8 };

	public final static byte[] R = { // 32 bytes
	(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xfe, (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
			(byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b, (byte) 0xbf,
			(byte) 0xd2, (byte) 0x5e, (byte) 0x8c, (byte) 0xd0, (byte) 0x36,
			(byte) 0x41, (byte) 0x41 };

	private static final byte K = (byte) 0x01;

	public static boolean setCommonCurveParameters(ECKey key) {
		try {
			key.setA(A, (short) 0, (short) A.length);
			key.setB(B, (short) 0, (short) B.length);
			key.setFieldFP(FP, (short) 0, (short) FP.length);
			key.setG(G, (short) 0, (short) G.length);
			key.setR(R, (short) 0, (short) R.length);
			key.setK(K);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	static public KeyPair newKeyPair() {
		KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

		ECPrivateKey ecPrv = (ECPrivateKey) kp.getPrivate();
		setCommonCurveParameters(ecPrv);
		ECPublicKey ecPub = (ECPublicKey) kp.getPublic();
		setCommonCurveParameters(ecPub);
		return kp;
	}
}
