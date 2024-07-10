/*
 * Copyright (C) CoolBitX Technology - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package coolbitx;

import javacard.framework.Util;
import javacard.security.RandomData;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public final class NonceUtil {
	private static RandomData random;
	public static byte[] PWD_MAX = { (byte) 0x05, (byte) 0xF5, (byte) 0xE0,
			(byte) 0xFF }; // 99999999
	public static byte[] PWD_MIN = { (byte) 0x00, (byte) 0x01, (byte) 0x86,
			(byte) 0xA0 }; // 100000

	public static byte[] INDEX_MAX = { (byte) 0x7f, (byte) 0xff, (byte) 0xff,
			(byte) 0xff };
	public static byte[] INDEX_MIN = { (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00 };

	public static void init() {
		random = RandomData.getInstance(RandomData.ALG_TRNG);
	}

	public static void uninit() {
		random = null;
	}

	public static void randomNonce(byte[] buf, short offset, short length) {
		random.nextBytes(buf, offset, length);
	}

	public static void randomRange(byte[] destBuf, short destOffset,
			short nonceLength, byte[] max, byte[] min) {
		boolean outOfRange;
		do {
			outOfRange = false;
			random.nextBytes(destBuf, destOffset, nonceLength);
			if (Util.arrayCompare(destBuf, destOffset, max, (short) 0,
					nonceLength) == 1) {
				outOfRange = true;
			}
			if (Util.arrayCompare(destBuf, destOffset, min, (short) 0,
					nonceLength) == -1) {
				outOfRange = true;
			}
		} while (outOfRange);

	}
}
