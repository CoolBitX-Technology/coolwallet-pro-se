/**
 * 
 */
package coolbitx.sio;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class StoreApplet extends Applet implements AppletEvent {
	private static final byte[] serverAid = { 'C', 'o', 'o', 'l', 'W', 'a',
			'l', 'l', 'e', 't', 'P', 'R', 'O' };
	private static boolean isCardNumberSet = false;
	AID serverAppAid;
	StoreObject sio;
	GenuineKey genuineKey;

	public StoreApplet() {
		serverAppAid = new AID(serverAid, (short) 0, (byte) serverAid.length);
		sio = new StoreObject();
		genuineKey = new GenuineKey();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		byte aidLength = bArray[bOffset++];
		short aidOffset = bOffset;
		bOffset += aidLength;
		byte controlLength = bArray[bOffset++];
		bOffset += controlLength;
		new StoreApplet().register(bArray, aidOffset, aidLength);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		if (!isCardNumberSet) {
			byte[] buf = apdu.getBuffer();
			if (buf[ISO7816.OFFSET_CLA] != (byte) 0x80) {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}
			if (buf[ISO7816.OFFSET_INS] != (byte) 0x00) {
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
			apdu.setIncomingAndReceive();
			short dataLength = apdu.getIncomingLength();
			short dataOffset = apdu.getOffsetCdata();
			sio.setCardId(buf, dataOffset, (byte) dataLength);
			isCardNumberSet = true;
		} else {
			ISOException.throwIt((short) 0x6789);
		}
	}

	public final void uninstall() {
		serverAppAid = null;
		sio = null;
		genuineKey = null;
		JCSystem.requestObjectDeletion();
	}

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		if (clientAID.equals(serverAppAid) == false) {
			return null;
		}
		switch (parameter) {
		case 0:
			return sio;
		}
		return null;
	}

}
