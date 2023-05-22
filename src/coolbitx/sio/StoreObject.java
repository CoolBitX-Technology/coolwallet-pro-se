/**
 * 
 */
package coolbitx.sio;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class StoreObject implements StoreInterface {

	public StoreObject() {
		haveBackupData = false;
		expSeqNo = Parameter.ZERO;
		dataLength = Parameter.ZERO;
		dataStore = new byte[Parameter.DATASTORE_LENGTH];
		checkSum = new byte[MessageDigest.LENGTH_SHA_256];
		cardIdLength = 0;
		cardId = new byte[250];
	}

	private boolean haveBackupData;
	private byte expSeqNo;
	private short dataLength;
	private byte[] dataStore;
	private byte[] checkSum;
	private byte cardIdLength;
	private byte[] cardId;
	private byte[] mainKey = { (byte) 0x0f, (byte) 0x0b, (byte) 0x32,
			(byte) 0xdb, (byte) 0x8e, (byte) 0x0e, (byte) 0xef, (byte) 0xd9,
			(byte) 0x29, (byte) 0x97, (byte) 0x23, (byte) 0xd0, (byte) 0xd8,
			(byte) 0xbc, (byte) 0xd7, (byte) 0x23, (byte) 0x0b, (byte) 0x38,
			(byte) 0xd2, (byte) 0x04, (byte) 0x3c, (byte) 0xfc, (byte) 0xe8,
			(byte) 0x72, (byte) 0x62, (byte) 0x9f, (byte) 0x60, (byte) 0x5b,
			(byte) 0xcb, (byte) 0xd1, (byte) 0x6c, (byte) 0xff, (byte) 0x2c,
			(byte) 0x46, (byte) 0xcb, (byte) 0x15, (byte) 0xdf, (byte) 0x02,
			(byte) 0x37, (byte) 0xd8, (byte) 0x6c, (byte) 0x21, (byte) 0x66,
			(byte) 0x90, (byte) 0xeb, (byte) 0xde, (byte) 0xe5, (byte) 0xce,
			(byte) 0xeb, (byte) 0x19, (byte) 0x39, (byte) 0x6a, (byte) 0xc1,
			(byte) 0xcc, (byte) 0x69, (byte) 0xe1, (byte) 0xbf, (byte) 0x82,
			(byte) 0x95, (byte) 0x55, (byte) 0x5c, (byte) 0xf3, (byte) 0x4e,
			(byte) 0xf9 };

	public boolean isDataBackup() {
		return haveBackupData;
	}

	public void setData(byte[] buf, short offset, short length, byte seqNo,
			boolean isLastData) {
		if (haveBackupData) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		if (expSeqNo != seqNo) {
			ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
		}
		if ((short) (dataLength + length) > Parameter.DATASTORE_LENGTH) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
		dataLength = Util.arrayCopyNonAtomic(buf, offset, dataStore,
				dataLength, length);
		expSeqNo++;
		// if this is the last data, check the checksum
		if (isLastData) {
			dataLength -= 32;
			MessageDigest.OneShot dig = null;
			try {
				dig = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
				short res = dig.doFinal(dataStore, Parameter.ZERO, dataLength,
						checkSum, Parameter.ZERO);
				short compare = Util.arrayCompare(checkSum, Parameter.ZERO,
						dataStore, dataLength, res);
				if (compare != 0) {
					reset();
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				expSeqNo = Parameter.ZERO;
				haveBackupData = true;
			} catch (CryptoException ce) {
				ISOException.throwIt(ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
			} finally {
				if (dig != null) {
					dig.close();
					dig = null;
				}
			}
		}
	}

	public short getDataLength() {
		if (!haveBackupData) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		return dataLength;
	}

	public short getData(byte[] destBuf, short destOffset, byte seqNo) {
		if (!haveBackupData) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		short returnLength;
		if ((short) ((seqNo + 1) * 250) < dataLength) {
			returnLength = 250;
		} else {
			returnLength = (short) (dataLength - seqNo * 250);
		}
		Util.arrayCopyNonAtomic(dataStore, (short) (seqNo * 250), destBuf,
				destOffset, returnLength);
		return returnLength;
	}

	public void setCardId(byte[] bArray, short bOffset, byte bLength) {
		Util.arrayCopyNonAtomic(bArray, bOffset, cardId, Parameter.ZERO,
				bLength);
		cardIdLength = bLength;
	}

	public short getCardId(byte[] destBuf, short destOffset) {
		Util.arrayCopyNonAtomic(cardId, Parameter.ZERO, destBuf, destOffset,
				cardIdLength);
		return cardIdLength;
	}

	public short getKey(byte[] destBuf, short destOffset) {
		Util.arrayCopyNonAtomic(mainKey, Parameter.ZERO, destBuf, destOffset,
				Parameter.KEY_LENGTH);
		return Parameter.KEY_LENGTH;
	}

	public void reset() {
		haveBackupData = false;
		expSeqNo = Parameter.ZERO;
		dataLength = Parameter.ZERO;
		Util.arrayFillNonAtomic(dataStore, Parameter.ZERO,
				(short) (dataStore.length), (byte) 0);
		Util.arrayFillNonAtomic(checkSum, Parameter.ZERO,
				(short) (checkSum.length), (byte) 0);
	}

}
