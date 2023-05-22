/**
 * 
 */
package coolbitx;

import javacard.framework.JCSystem;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class FlowCounter {
	public static final short initValue = 0x10A0;

	private static short[] flow;

	public static void init() {
		flow = JCSystem.makeTransientShortArray((short) 1,
				JCSystem.CLEAR_ON_DESELECT);
	}
	
	public static void uninit() {
		flow = null;
	}


	public static void reset() {
		flow[0] = initValue;
	}

	public static void increase() {
		flow[0]++;
	}

	public static void checkValue(short counterOffset) {
		Check.checkValue(flow[0], (short) (initValue + counterOffset),
				(short) 0x6f10);
	}

}
