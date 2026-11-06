package org.globalplatform;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.Shareable;

/**
 * Simulator stand-in for the GlobalPlatform API, which jcardsim does not
 * have. Same constants and methods as gp230.jar.
 */
public interface SecureChannel extends Shareable {
	byte AUTHENTICATED = (byte) 0x80;
	byte C_DECRYPTION = 0x02;
	byte C_MAC = 0x01;
	byte R_ENCRYPTION = 0x20;
	byte R_MAC = 0x10;
	byte NO_SECURITY_LEVEL = 0x00;
	byte ANY_AUTHENTICATED = 0x40;

	short processSecurity(APDU apdu) throws ISOException;

	short wrap(byte[] baBuffer, short sOffset, short sLength) throws ISOException;

	short unwrap(byte[] baBuffer, short sOffset, short sLength) throws ISOException;

	short decryptData(byte[] baBuffer, short sOffset, short sLength) throws ISOException;

	short encryptData(byte[] baBuffer, short sOffset, short sLength) throws ISOException;

	void resetSecurity();

	byte getSecurityLevel();
}
