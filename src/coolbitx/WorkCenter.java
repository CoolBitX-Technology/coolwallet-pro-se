/**
 * 
 */
package coolbitx;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class WorkCenter {
	private static byte[] workspace0;
	public static byte[] workspace1;
	private static short[] workOffset;
	private static byte ASSIGN_ARRAY;
	public static final byte NOT_ASSIGN = -1;
	public static final byte WORK = 0;
	public static final byte WORK1 = 1;

	public static void init() {
		workOffset = JCSystem.makeTransientShortArray((short) 2,
				JCSystem.CLEAR_ON_DESELECT);
		workspace0 = JCSystem.makeTransientByteArray((short) 800,
				JCSystem.CLEAR_ON_DESELECT);
		workspace1 = JCSystem.makeTransientByteArray((short) 800,
				JCSystem.CLEAR_ON_DESELECT);
		reset();
	}

	public static void uninit() {
		workOffset = null;
		workspace0 = null;
		workspace1 = null;
	}

	public static void reset() {
		ASSIGN_ARRAY = NOT_ASSIGN;
		workOffset[(short) (WORK)] = 0;
		workOffset[(short) (WORK1)] = 0;
	}

	public final static byte[] getWorkspaceArray(byte index) {
		switch (index) {
		case WORK:
			ASSIGN_ARRAY = WORK;
			return workspace0;
		case WORK1:
			ASSIGN_ARRAY = WORK1;
			return workspace1;
		default:
			ISOException.throwIt((short) 0x6F12);
			return null;
		}
	}

	public final static short getWorkspaceOffset(short length) {
		if (ASSIGN_ARRAY == NOT_ASSIGN) {
			ISOException.throwIt((short) 0x6F13);
		}
		short offset = workOffset[(short) (ASSIGN_ARRAY)];
		Util.arrayFillNonAtomic(getWorkspaceArray(ASSIGN_ARRAY), offset,
				length, (byte) 0);
		workOffset[(short) (ASSIGN_ARRAY)] += length;
		ASSIGN_ARRAY = NOT_ASSIGN;
		return offset;
	}

	public static void release(short index, short length) {
		workOffset[(short) (index)] -= length;
	}

	public static void checkAPDUEmpty() {
		if (workOffset[0] > 0) {
			ISOException.throwIt((short) 0x6EA5);
		}
	}

}
