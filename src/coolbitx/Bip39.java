/**
 * 
 */
package coolbitx;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Bip39 {
	// private static byte[] mnemonic = { 'm', 'n', 'e', 'm', 'o', 'n', 'i',
	// 'c',
	// 0x00, 0x00, 0x00, 0x01 };

	public static byte[] sum;
	public static byte[] zeroSum;
	private static short[] index;
	private static short strength = 0;

	public static void init() {
		sum = new byte[4];
		zeroSum = new byte[4];
		index = new short[24];
	}

	public static void uninit() {
		// mnemonic = null;
		// ONE = null;
		sum = null;
		zeroSum = null;
		index = null;
	}

	public static void createWallet(short inputStrength) {
		strength = inputStrength;
		short entLength = (short) (strength / 3 * 4);// bytes

		// CS = ENT / 32
		// MS = (ENT + CS) / 11
		//
		// | ENT | CS | ENT+CS | MS | BYTES |
		// +-----+----+--------+----+-------+
		// | 128 | 04 | ---132 | 12 | ---16 |
		// | 160 | 05 | ---165 | 15 | ---20 |
		// | 192 | 06 | ---198 | 18 | ---24 |
		// | 224 | 07 | ---231 | 21 | ---28 |
		// | 256 | 08 | ---264 | 24 | ---32 |

		// gen entropy
		byte[] ent = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short entOffset = WorkCenter
				.getWorkspaceOffset((short) (entLength + 32));
		NonceUtil.randomNonce(ent, entOffset, entLength);

		// hash entropy and take first few bits as checksum
		ShaUtil.SHA256(ent, entOffset, entLength, ent,
				(short) (entOffset + entLength));

		short buffer = 0, bi = 0, ei = entOffset;
		for (short i = 0; i < (short) (strength * 2); i++) {
			if (bi < 8) {
				buffer |= (ent[(short) (ei)] & 0x00FF) << (7 - bi);
				bi += 8;
				ei++;
			}
			if (i % 2 == 0) {
				index[(short) (i / 2)] = (short) ((buffer & 0x7E00) >> 4);
				buffer <<= 6;
				bi -= 6;
			} else {
				index[(short) (i / 2)] |= (short) ((buffer & 0x7C00) >> 10);
				buffer <<= 5;
				bi -= 5;
			}
		}
	}

	public static short getNumberMnemonic(byte[] destBuf, short destOffset) {
		byte[] workspace = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workOffset = WorkCenter.getWorkspaceOffset((short) 4);
		Common.clearArray(sum);
		for (short i = 0; i < strength; i++) {
			// clean workspace
			Util.arrayFillNonAtomic(workspace, workOffset, (short) 4, (byte) 0);
			// mnemonic * 48 + 1
			Util.setShort(workspace, (short) (workOffset + 2),
					index[(short) (i)]);
			NumberUtil.multiplyAndAdd(workspace, workOffset, (short) 4,
					(short) 256, (short) 48, (short) 1);
			// convert to BCD
			NumberUtil.baseConvert(workspace, workOffset, (short) 4,
					NumberUtil.binaryCharset, destBuf, destOffset, (short) 3,
					NumberUtil.bcdCharset);
			destOffset += 3;
			// add sum
			MathUtil.add(sum, Common.OFFSET_ZERO, (short) 4, workspace, workOffset,
					sum, Common.OFFSET_ZERO);
		}
		WorkCenter.release(WorkCenter.WORK, (short) 4);
		return (short) (strength * 3);
	}

	public static short getMnemonicIndex(byte[] destBuf, short destOffset) {
		short initDestOffset = destOffset;

		for (short i = 0; i < strength; i++) {
			Util.setShort(destBuf, destOffset, index[i]);
			destOffset += 2;
		}
		return (short) (destOffset - initDestOffset);
	}

}
