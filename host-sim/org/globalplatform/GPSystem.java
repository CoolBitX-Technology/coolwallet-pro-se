package org.globalplatform;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Simulator stand-in for the GlobalPlatform API, which jcardsim does not
 * have. The simulator has no Security Domain keys, so the secure channel
 * never authenticates: the handshake returns 6D00 and commands that need a
 * C-MAC are rejected by SecureSession.
 */
public class GPSystem {

	private static final SecureChannel CHANNEL = new SecureChannel() {
		public short processSecurity(APDU apdu) {
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			return 0;
		}

		public short wrap(byte[] baBuffer, short sOffset, short sLength) {
			return sLength;
		}

		public short unwrap(byte[] baBuffer, short sOffset, short sLength) {
			return sLength;
		}

		public short decryptData(byte[] baBuffer, short sOffset, short sLength) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return 0;
		}

		public short encryptData(byte[] baBuffer, short sOffset, short sLength) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return 0;
		}

		public void resetSecurity() {
		}

		public byte getSecurityLevel() {
			return NO_SECURITY_LEVEL;
		}
	};

	public static SecureChannel getSecureChannel() {
		return CHANNEL;
	}
}
