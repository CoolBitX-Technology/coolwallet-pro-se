package coolbitx;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * GlobalPlatform secure channel (SCP02 on Pro) of the Security Domain this
 * applet is installed under. The backend holding the SD keys authenticates
 * through the applet, so a command carrying a C-MAC comes from the backend
 * and a response carrying an R-MAC comes from this genuine card, whatever
 * the app relaying them does.
 *
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class SecureSession {

	public static final byte CLA_SECURE_MESSAGING = (byte) 0x84;
	public static final byte INS_INITIALIZE_UPDATE = 0x50;
	public static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

	private static final short LENGTH_HOST_CHALLENGE = 8;

	// INITIALIZE UPDATE is 80 50, the same as hi; its data is the 8-byte host
	// challenge, while hi carries a 20-byte appId
	public static boolean isSecureCommand(byte[] apduBuf) {
		byte cla = apduBuf[ISO7816.OFFSET_CLA];
		if (cla == CLA_SECURE_MESSAGING) {
			return true;
		}
		return cla == (byte) 0x80 && apduBuf[ISO7816.OFFSET_INS] == INS_INITIALIZE_UPDATE
				&& apduBuf[ISO7816.OFFSET_LC] == LENGTH_HOST_CHALLENGE;
	}

	public static void initializeUpdate(APDU apdu) {
		short length = GPSystem.getSecureChannel().processSecurity(apdu);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
	}

	public static void externalAuthenticate(APDU apdu) {
		short length = GPSystem.getSecureChannel().processSecurity(apdu);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
	}

	/**
	 * Receives the command and verifies its C-MAC. unwrap() lets a command
	 * through unchecked when the session has no C-MAC, so the security level
	 * is checked first.
	 *
	 * @return length of the command data, at ISO7816.OFFSET_CDATA
	 */
	public static short unwrap(APDU apdu) {
		SecureChannel channel = GPSystem.getSecureChannel();
		if ((channel.getSecurityLevel() & SecureChannel.C_MAC) == 0) {
			ISOException.throwIt(ErrorMessage.SECURE_NO_C_MAC);
		}
		byte[] buf = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		channel.unwrap(buf, Common.OFFSET_ZERO, (short) (ISO7816.OFFSET_CDATA + length));
		return (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
	}

	public static void requireRMac() {
		if ((GPSystem.getSecureChannel().getSecurityLevel() & SecureChannel.R_MAC) == 0) {
			ISOException.throwIt(ErrorMessage.SECURE_NO_R_MAC);
		}
	}

	/**
	 * Sends buf[0, length) with an R-MAC when the session has one, so the
	 * backend can keep verifying the responses of the session.
	 */
	public static void send(APDU apdu, short length) {
		byte[] buf = apdu.getBuffer();
		SecureChannel channel = GPSystem.getSecureChannel();
		if ((channel.getSecurityLevel() & SecureChannel.R_MAC) != 0) {
			// wrap() protects the status word too, then strips it
			Util.setShort(buf, length, ISO7816.SW_NO_ERROR);
			length = channel.wrap(buf, Common.OFFSET_ZERO, (short) (length + 2));
		}
		apdu.setOutgoingAndSend(Common.OFFSET_ZERO, length);
	}

	public static void reset() {
		GPSystem.getSecureChannel().resetSecurity();
	}
}
