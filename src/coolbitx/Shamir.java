package coolbitx;

import javacard.framework.Util;

public class Shamir {
	private static byte padLength = 16;
	private static final short maxShares = (short) 255; // 2^8 - 1
	private static final byte[] calculatedLogarithms = { (byte) 0, (byte) 255,
			(byte) 1, (byte) 25, (byte) 2, (byte) 50, (byte) 26, (byte) 198,
			(byte) 3, (byte) 223, (byte) 51, (byte) 238, (byte) 27, (byte) 104,
			(byte) 199, (byte) 75, (byte) 4, (byte) 100, (byte) 224, (byte) 14,
			(byte) 52, (byte) 141, (byte) 239, (byte) 129, (byte) 28,
			(byte) 193, (byte) 105, (byte) 248, (byte) 200, (byte) 8,
			(byte) 76, (byte) 113, (byte) 5, (byte) 138, (byte) 101, (byte) 47,
			(byte) 225, (byte) 36, (byte) 15, (byte) 33, (byte) 53, (byte) 147,
			(byte) 142, (byte) 218, (byte) 240, (byte) 18, (byte) 130,
			(byte) 69, (byte) 29, (byte) 181, (byte) 194, (byte) 125,
			(byte) 106, (byte) 39, (byte) 249, (byte) 185, (byte) 201,
			(byte) 154, (byte) 9, (byte) 120, (byte) 77, (byte) 228,
			(byte) 114, (byte) 166, (byte) 6, (byte) 191, (byte) 139,
			(byte) 98, (byte) 102, (byte) 221, (byte) 48, (byte) 253,
			(byte) 226, (byte) 152, (byte) 37, (byte) 179, (byte) 16,
			(byte) 145, (byte) 34, (byte) 136, (byte) 54, (byte) 208,
			(byte) 148, (byte) 206, (byte) 143, (byte) 150, (byte) 219,
			(byte) 189, (byte) 241, (byte) 210, (byte) 19, (byte) 92,
			(byte) 131, (byte) 56, (byte) 70, (byte) 64, (byte) 30, (byte) 66,
			(byte) 182, (byte) 163, (byte) 195, (byte) 72, (byte) 126,
			(byte) 110, (byte) 107, (byte) 58, (byte) 40, (byte) 84,
			(byte) 250, (byte) 133, (byte) 186, (byte) 61, (byte) 202,
			(byte) 94, (byte) 155, (byte) 159, (byte) 10, (byte) 21,
			(byte) 121, (byte) 43, (byte) 78, (byte) 212, (byte) 229,
			(byte) 172, (byte) 115, (byte) 243, (byte) 167, (byte) 87,
			(byte) 7, (byte) 112, (byte) 192, (byte) 247, (byte) 140,
			(byte) 128, (byte) 99, (byte) 13, (byte) 103, (byte) 74,
			(byte) 222, (byte) 237, (byte) 49, (byte) 197, (byte) 254,
			(byte) 24, (byte) 227, (byte) 165, (byte) 153, (byte) 119,
			(byte) 38, (byte) 184, (byte) 180, (byte) 124, (byte) 17,
			(byte) 68, (byte) 146, (byte) 217, (byte) 35, (byte) 32,
			(byte) 137, (byte) 46, (byte) 55, (byte) 63, (byte) 209, (byte) 91,
			(byte) 149, (byte) 188, (byte) 207, (byte) 205, (byte) 144,
			(byte) 135, (byte) 151, (byte) 178, (byte) 220, (byte) 252,
			(byte) 190, (byte) 97, (byte) 242, (byte) 86, (byte) 211,
			(byte) 171, (byte) 20, (byte) 42, (byte) 93, (byte) 158,
			(byte) 132, (byte) 60, (byte) 57, (byte) 83, (byte) 71, (byte) 109,
			(byte) 65, (byte) 162, (byte) 31, (byte) 45, (byte) 67, (byte) 216,
			(byte) 183, (byte) 123, (byte) 164, (byte) 118, (byte) 196,
			(byte) 23, (byte) 73, (byte) 236, (byte) 127, (byte) 12,
			(byte) 111, (byte) 246, (byte) 108, (byte) 161, (byte) 59,
			(byte) 82, (byte) 41, (byte) 157, (byte) 85, (byte) 170,
			(byte) 251, (byte) 96, (byte) 134, (byte) 177, (byte) 187,
			(byte) 204, (byte) 62, (byte) 90, (byte) 203, (byte) 89, (byte) 95,
			(byte) 176, (byte) 156, (byte) 169, (byte) 160, (byte) 81,
			(byte) 11, (byte) 245, (byte) 22, (byte) 235, (byte) 122,
			(byte) 117, (byte) 44, (byte) 215, (byte) 79, (byte) 174,
			(byte) 213, (byte) 233, (byte) 230, (byte) 231, (byte) 173,
			(byte) 232, (byte) 116, (byte) 214, (byte) 244, (byte) 234,
			(byte) 168, (byte) 80, (byte) 88, (byte) 175 };

	private static final byte[] calculatedExponents = { (byte) 1, (byte) 2,
			(byte) 4, (byte) 8, (byte) 16, (byte) 32, (byte) 64, (byte) 128,
			(byte) 29, (byte) 58, (byte) 116, (byte) 232, (byte) 205,
			(byte) 135, (byte) 19, (byte) 38, (byte) 76, (byte) 152, (byte) 45,
			(byte) 90, (byte) 180, (byte) 117, (byte) 234, (byte) 201,
			(byte) 143, (byte) 3, (byte) 6, (byte) 12, (byte) 24, (byte) 48,
			(byte) 96, (byte) 192, (byte) 157, (byte) 39, (byte) 78,
			(byte) 156, (byte) 37, (byte) 74, (byte) 148, (byte) 53,
			(byte) 106, (byte) 212, (byte) 181, (byte) 119, (byte) 238,
			(byte) 193, (byte) 159, (byte) 35, (byte) 70, (byte) 140, (byte) 5,
			(byte) 10, (byte) 20, (byte) 40, (byte) 80, (byte) 160, (byte) 93,
			(byte) 186, (byte) 105, (byte) 210, (byte) 185, (byte) 111,
			(byte) 222, (byte) 161, (byte) 95, (byte) 190, (byte) 97,
			(byte) 194, (byte) 153, (byte) 47, (byte) 94, (byte) 188,
			(byte) 101, (byte) 202, (byte) 137, (byte) 15, (byte) 30,
			(byte) 60, (byte) 120, (byte) 240, (byte) 253, (byte) 231,
			(byte) 211, (byte) 187, (byte) 107, (byte) 214, (byte) 177,
			(byte) 127, (byte) 254, (byte) 225, (byte) 223, (byte) 163,
			(byte) 91, (byte) 182, (byte) 113, (byte) 226, (byte) 217,
			(byte) 175, (byte) 67, (byte) 134, (byte) 17, (byte) 34, (byte) 68,
			(byte) 136, (byte) 13, (byte) 26, (byte) 52, (byte) 104,
			(byte) 208, (byte) 189, (byte) 103, (byte) 206, (byte) 129,
			(byte) 31, (byte) 62, (byte) 124, (byte) 248, (byte) 237,
			(byte) 199, (byte) 147, (byte) 59, (byte) 118, (byte) 236,
			(byte) 197, (byte) 151, (byte) 51, (byte) 102, (byte) 204,
			(byte) 133, (byte) 23, (byte) 46, (byte) 92, (byte) 184,
			(byte) 109, (byte) 218, (byte) 169, (byte) 79, (byte) 158,
			(byte) 33, (byte) 66, (byte) 132, (byte) 21, (byte) 42, (byte) 84,
			(byte) 168, (byte) 77, (byte) 154, (byte) 41, (byte) 82,
			(byte) 164, (byte) 85, (byte) 170, (byte) 73, (byte) 146,
			(byte) 57, (byte) 114, (byte) 228, (byte) 213, (byte) 183,
			(byte) 115, (byte) 230, (byte) 209, (byte) 191, (byte) 99,
			(byte) 198, (byte) 145, (byte) 63, (byte) 126, (byte) 252,
			(byte) 229, (byte) 215, (byte) 179, (byte) 123, (byte) 246,
			(byte) 241, (byte) 255, (byte) 227, (byte) 219, (byte) 171,
			(byte) 75, (byte) 150, (byte) 49, (byte) 98, (byte) 196,
			(byte) 149, (byte) 55, (byte) 110, (byte) 220, (byte) 165,
			(byte) 87, (byte) 174, (byte) 65, (byte) 130, (byte) 25, (byte) 50,
			(byte) 100, (byte) 200, (byte) 141, (byte) 7, (byte) 14, (byte) 28,
			(byte) 56, (byte) 112, (byte) 224, (byte) 221, (byte) 167,
			(byte) 83, (byte) 166, (byte) 81, (byte) 162, (byte) 89,
			(byte) 178, (byte) 121, (byte) 242, (byte) 249, (byte) 239,
			(byte) 195, (byte) 155, (byte) 43, (byte) 86, (byte) 172,
			(byte) 69, (byte) 138, (byte) 9, (byte) 18, (byte) 36, (byte) 72,
			(byte) 144, (byte) 61, (byte) 122, (byte) 244, (byte) 245,
			(byte) 247, (byte) 243, (byte) 251, (byte) 235, (byte) 203,
			(byte) 139, (byte) 11, (byte) 22, (byte) 44, (byte) 88, (byte) 176,
			(byte) 125, (byte) 250, (byte) 233, (byte) 207, (byte) 131,
			(byte) 27, (byte) 54, (byte) 108, (byte) 216, (byte) 173,
			(byte) 71, (byte) 142, (byte) 1 };

	public static void derive(byte[] shares, short sharesOffset,
			short sharesLength, short requiredShares, byte[] destBuf,
			short destOffset) {
		byte[] x = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short xOffset = WorkCenter.getWorkspaceOffset(requiredShares);
		byte[] y = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short yOffset = WorkCenter
				.getWorkspaceOffset((short) (requiredShares * sharesLength));

		byte[] res = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short resOffset = WorkCenter.getWorkspaceOffset((short) (sharesLength));

		for (short i = 0; i < requiredShares; i++) {
			x[i] = shares[sharesOffset + i * (sharesLength + 1)];
		}

		for (short i = 0; i < sharesLength; i++) {
			for (short j = 0; j < requiredShares; j++) {
				y[yOffset + (i * requiredShares) + j] = shares[sharesOffset
						+ (j + 1) * (sharesLength + 1) - i - 1];
			}
		}
		boolean findFirstOne = false;
		short destLength = sharesLength;
		for (short i = 0; i < sharesLength; i++) {
			byte value = lagrange(x, xOffset, requiredShares, y,
					(short) (yOffset + i * requiredShares));
			res[resOffset + sharesLength - 1 - i] = value;

			if (!findFirstOne) {
				destLength--;
				if (value == 1) {
					findFirstOne = true;
				}
			}
		}

		Util.arrayCopyNonAtomic(res, resOffset, destBuf, destOffset, destLength);
		MathUtil.reverse(destBuf, destOffset, destLength);
	}

	private static byte lagrange(byte[] x, short xOffset, short xLength,
			byte[] y, short yOffset) {
		short sum = 0;
		for (short i = 0; i < xLength; i++) {
			short yI = (short) (y[yOffset + i] & 0x00ff);
			if (yI != 0) {
				short product = (short) (calculatedLogarithms[yI] & 0x00ff);
				for (short j = 0; j < xLength; j++) {
					if (i != j) {
						short xI = (short) (x[xOffset + i] & 0x00ff);
						short xJ = (short) (x[xOffset + j] & 0x00ff);
						short calculatedLogarithmsA = (short) (calculatedLogarithms[0 ^ xJ] & 0x00ff);
						short calculatedLogarithmsB = (short) (calculatedLogarithms[xI
								^ xJ] & 0x00ff);
						product = (short) ((product + calculatedLogarithmsA
								- calculatedLogarithmsB + maxShares) % maxShares);
					}
				}
				sum = (short) (sum ^ (short) (calculatedExponents[product] & 0x00ff));
			}
		}
		return (byte) (sum & 0x00ff);
	}

	public static short sperate(byte[] secret, short offset, short length,
			short totalShares, short requireShares, byte[] destBuf,
			short destOffset) {
		short workLength = (short) (((length / padLength) + 1) * padLength);
		byte[] workBuf = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workOffset = WorkCenter.getWorkspaceOffset(workLength);

		short p = Util.arrayCopyNonAtomic(secret, offset, workBuf, workOffset,
				length);
		MathUtil.reverse(workBuf, workOffset, length);
		workBuf[p++] = 1;
		// pad zero
		Util.arrayFillNonAtomic(workBuf, p, (short) (workLength - length - 1),
				(byte) 0);

		return sperateSecret(workBuf, workOffset, workLength, totalShares,
				requireShares, destBuf, destOffset);
	}

	private static short sperateSecret(byte[] secret, short secretOffset,
			short secretLength, short totalShares, short requiredShares,
			byte[] destBuf, short destOffset) {
		byte[] y = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short yOffset = WorkCenter
				.getWorkspaceOffset((short) (totalShares * secretLength));

		byte[] subShare = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short subShareOffset = WorkCenter.getWorkspaceOffset(totalShares);

		for (short i = 0; i < secretLength; i++) {
			calculateRandomizedShares(secret[i], totalShares, requiredShares,
					subShare, subShareOffset);
			for (short j = 1; j <= totalShares; j++) {
				y[(short) (yOffset + (j * secretLength) - i - 1)] = subShare[(short) (subShareOffset
						+ j - 1)];
			}
		}

		for (short i = 0; i < totalShares; i++) {
			short p = (short) (i * (secretLength + 1));
			destBuf[(short) (destOffset + p++)] = (byte) (i + 1);
			Util.arrayCopyNonAtomic(y, (short) (yOffset + i * secretLength),
					destBuf, p, secretLength);
		}

		return (short) (totalShares * (secretLength + 1));
	}

	private static short calculateRandomizedShares(byte secret,
			short totalShares, short requiredShares, byte[] destBuf,
			short destOffset) {
		byte[] y = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short yOffset = WorkCenter.getWorkspaceOffset(totalShares);

		byte[] coefficients = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short coefficientsOffset = WorkCenter
				.getWorkspaceOffset(requiredShares);

		coefficients[coefficientsOffset] = secret;

		// Pick random coefficients for our polynomial function
		for (short i = 1; i < requiredShares; i++) {
			NonceUtil.randomNonce(coefficients,
					(short) (coefficientsOffset + i), (short) 1);
		}

		// Calculate the y value of each share based on f(x) when using our new
		// random polynomial function
		for (short i = 1, len = (short) (totalShares + 1); i < len; i++) {
			y[(short) (yOffset + i - 1)] = calculateFofX(i, coefficients,
					coefficientsOffset, requiredShares);
		}
		Util.arrayCopyNonAtomic(y, yOffset, destBuf, destOffset, totalShares);

		return totalShares;
	}

	private static byte calculateFofX(short x, byte[] coefficients,
			short coefficientsOffset, short coefficientsLength) {
		short logX = (short) (calculatedLogarithms[x] & 0x00ff);
		short fx = 0;
		for (short i = (short) (coefficientsLength - 1); i >= 0; i--) {
			if (fx != 0) {
				short calculatedLogarithm = (short) (calculatedLogarithms[(short) (fx & 0x00ff)] & 0x00ff);
				short coefficient = (short) (coefficients[(short) (coefficientsOffset + i)] & 0x00ff);
				short calculatedExponent = (short) ((calculatedExponents[(short) ((logX + calculatedLogarithm) % maxShares)]) & 0x00ff);
				fx = (short) (calculatedExponent ^ coefficient);
			} else {
				// if f(0) then we just return the coefficient as it's just
				// equivalent to the Y offset. Using the exponent table would
				// result
				// in an incorrect answer
				fx = (short) ((coefficients[(short) (coefficientsOffset + i)]) & 0x00ff);
			}
		}
		return (byte) (fx & 0x00ff);
	}
}
