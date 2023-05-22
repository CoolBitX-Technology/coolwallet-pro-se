/**
 * 
 */
package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class BackupController {
	private static final byte VERSION = 1;
	
	private static final byte BIP32 = 1;
	private static final byte DEVICE = 2;
	private static final byte WALLET_STATUS = 3;
	private static final byte DISPLAY_TYPE = 4;
	private static final byte BIP32ED25519 = 5;

	public static short backup(byte[] destBuf, short destOffset) {
		short initOffset = destOffset;
		destBuf[destOffset++] = VERSION;
		short backupLength = Bip32.backupData(destBuf, destOffset);
		destOffset = formatBackupData(destBuf, destOffset, backupLength, BIP32);
		backupLength = Device.backupData(destBuf, destOffset);
		destOffset = formatBackupData(destBuf, destOffset, backupLength, DEVICE);
		destBuf[destOffset] = CardInfo.getWalletStatus();
		destOffset = formatBackupData(destBuf, destOffset, (short) 1,
				WALLET_STATUS);
		destBuf[destOffset] = CardInfo.getDisplayType();
		destOffset = formatBackupData(destBuf, destOffset, (short) 1,
				DISPLAY_TYPE);
		// Make sure the backup process will proceed without cardano seed.
		if (Bip32Ed25519.isInit() == (byte) 1) {
			backupLength = Bip32Ed25519.backupData(destBuf, destOffset);
			destOffset = formatBackupData(destBuf, destOffset, backupLength, BIP32ED25519);
		}
		return (short) (destOffset - initOffset);
	}

	private static short formatBackupData(byte[] destBuf, short destOffset,
			short length, byte header) {
		Util.arrayCopyNonAtomic(destBuf, destOffset, destBuf,
				(short) (destOffset + 3), length);
		destBuf[destOffset++] = header;
		destOffset = Util.setShort(destBuf, destOffset, length);
		return (short) (destOffset + length);
	}

	public static void recover(byte[] buf, short offset, short length) {
		short endOffset = (short) (offset + length);
		byte version = buf[offset++];
		switch (version) {
		case (byte) 0x00:
			offset = Bip32.recoverData(buf, offset);
			offset = Device.recoverData(buf, offset);
			CardInfo.setWalletStatus(buf[offset++]);
			CardInfo.setDisplayType(buf[offset++], true);
			break;
		case (byte) 0x01:
			for (; offset < endOffset;) {
				byte header = buf[offset++];
				short dataLength = Util.getShort(buf, offset);
				offset += 2;
				switch (header) {
				case BIP32:
					Bip32.recoverData(buf, offset);
					break;
				case DEVICE:
					Device.recoverData(buf, offset);
					break;
				case WALLET_STATUS:
					CardInfo.setWalletStatus(buf[offset]);
					break;
				case DISPLAY_TYPE:
					CardInfo.setDisplayType(buf[offset], true);
					break;
				case BIP32ED25519:
					Bip32Ed25519.recoverData(buf, offset);
					break;
				default:
					ISOException.throwIt((short) 0x6111);
					break;
				}
				offset += dataLength;
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	}
}
