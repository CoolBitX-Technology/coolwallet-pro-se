package coolbitx;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 * Backs the wallet up to a CoolSeed backup card and restores it from one.
 *
 * The wallet data is a TLV list (type 1B || length 2B || value, with
 * BackupController's type numbers) cut into segments: the first carries 144
 * bytes of it, the others 148. Each segment is an EcdhUtil ciphertext for
 * the other card, so the app relaying them never sees the seed:
 *
 * first segment: version || backup ID(8B) || 1 || count || password(4B) || data
 * segment k:     version || backup ID(8B) || k || count || data
 *
 * The public keys come from the backend over the secure channel (see
 * SecureSession). Interface: cool-seed-se docs/backup-card-spec.md.
 *
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class CoolSeedBackup {
	private static final byte VERSION = 1;

	// Same type numbers as BackupController
	private static final byte TYPE_BIP32 = 1;
	private static final byte TYPE_BIP32ED25519 = 5;
	private static final short LENGTH_TLV_HEADER = 3;

	private static final short LENGTH_BACKUP_ID = 8;
	private static final short LENGTH_PASSWORD = 4;
	private static final short LENGTH_SEGMENT_HEADER = (short) (1 + LENGTH_BACKUP_ID + 2);
	private static final short OFFSET_SEGMENT_NUMBER = (short) (1 + LENGTH_BACKUP_ID);
	private static final short OFFSET_SEGMENT_COUNT = (short) (OFFSET_SEGMENT_NUMBER + 1);
	private static final short MAX_FIRST_SEGMENT_DATA = 144;
	private static final short MAX_SEGMENT_DATA = 148;
	private static final byte MAX_SEGMENT_COUNT = 13;
	private static final short MAX_DATA_LENGTH = 2000;
	// ephemeral public key || MAC || one to ten AES blocks
	private static final short MIN_SEGMENT_CIPHER =
			(short) (Common.LENGTH_PUBLICKEY + Common.LENGTH_MAC + 16);
	private static final short MAX_SEGMENT_CIPHER =
			(short) (Common.LENGTH_PUBLICKEY + Common.LENGTH_MAC + 160);
	private static final short MAX_CARD_NUMBER = 16;

	// Export: the CoolSeed key the backend verified, then the backup
	private static byte[] coolSeedKey;
	private static boolean coolSeedKeySet;
	private static byte[] backupId;
	private static byte[] password;
	private static boolean exportStarted;

	// Import: a one-time key for the segments, then the segments received
	private static KeyPair restoreKeyPair;
	private static boolean restoreKeyValid;
	private static byte[] importId;
	private static byte[] importData;
	private static short importLength;
	// Segment count of the import in progress, 0 when there is none
	private static byte importCount;
	private static byte importNext;

	public static void init() {
		coolSeedKey = new byte[Common.LENGTH_PUBLICKEY];
		backupId = new byte[LENGTH_BACKUP_ID];
		password = new byte[LENGTH_PASSWORD];
		restoreKeyPair = Secp256k1.newKeyPair();
		importId = new byte[LENGTH_BACKUP_ID];
		importData = new byte[MAX_DATA_LENGTH];
	}

	public static void uninit() {
		coolSeedKey = null;
		backupId = null;
		password = null;
		restoreKeyPair = null;
		importId = null;
		importData = null;
	}

	public static void reset() {
		coolSeedKeySet = false;
		clearExport();
		restoreKeyValid = false;
		clearImport();
	}

	/**
	 * Takes the CoolSeed public key the backend verified with the CoolSeed
	 * R-MAC: the key to export to, or during a restore the key every segment
	 * must come from. A new key drops the export or import in progress.
	 *
	 * @param buf CoolSeed public key(65B) || card number length(1B) || card
	 *            number(ASCII)
	 */
	public static void setCoolSeedKey(byte[] buf, short offset, short length) {
		if (length <= Common.LENGTH_PUBLICKEY || buf[offset] != 0x04) {
			ISOException.throwIt(ErrorMessage.COOLSEED_KEY_INVALID);
		}
		short cardNumberLength = buf[(short) (offset + Common.LENGTH_PUBLICKEY)];
		if (cardNumberLength < 1 || cardNumberLength > MAX_CARD_NUMBER
				|| length != (short) (Common.LENGTH_PUBLICKEY + 1 + cardNumberLength)) {
			ISOException.throwIt(ErrorMessage.COOLSEED_KEY_INVALID);
		}
		// The card number is for the user to compare on the screen, which
		// comes later
		Util.arrayCopy(buf, offset, coolSeedKey, Common.OFFSET_ZERO, Common.LENGTH_PUBLICKEY);
		coolSeedKeySet = true;
		clearExport();
		clearImport();
	}

	/**
	 * Starts an export with a new backup ID.
	 *
	 * @param buf password, 8 digits in BCD
	 */
	public static void startExport(byte[] buf, short offset, short length) {
		CardInfo.checkWalletStatusEqual(Common.WALLET_CREATED);
		if (!coolSeedKeySet) {
			ISOException.throwIt(ErrorMessage.COOLSEED_KEY_NOT_SET);
		}
		if (length != LENGTH_PASSWORD) {
			ISOException.throwIt(ErrorMessage.COOLSEED_PASSWORD_INVALID);
		}
		for (short i = 0; i < LENGTH_PASSWORD; i++) {
			byte digits = buf[(short) (offset + i)];
			if ((digits & 0xF0) > 0x90 || (digits & 0x0F) > 0x09) {
				ISOException.throwIt(ErrorMessage.COOLSEED_PASSWORD_INVALID);
			}
		}
		Util.arrayCopy(buf, offset, password, Common.OFFSET_ZERO, LENGTH_PASSWORD);
		NonceUtil.randomNonce(backupId, Common.OFFSET_ZERO, LENGTH_BACKUP_ID);
		exportStarted = true;
	}

	/**
	 * Encrypts segment number of the export for CoolSeed. The data is built
	 * again on every call, so a segment can be sent again after NFC drops.
	 */
	public static short getSegment(byte number, byte[] workBuf, short workOffset,
			byte[] destBuf, short destOffset) {
		checkExportStarted();
		short dataOffset = (short) (workOffset + LENGTH_BACKUP_ID);
		short dataLength = buildData(workBuf, dataOffset);
		byte count = getSegmentCount(dataLength);
		if (number < 1 || number > count) {
			clearWork(workBuf, workOffset, (short) (LENGTH_BACKUP_ID + dataLength));
			ISOException.throwIt(ErrorMessage.COOLSEED_SEGMENT_OUT_OF_RANGE);
		}

		short segmentOffset = (short) (dataOffset + dataLength);
		short p = segmentOffset;
		workBuf[p++] = VERSION;
		p = Util.arrayCopyNonAtomic(backupId, Common.OFFSET_ZERO, workBuf, p, LENGTH_BACKUP_ID);
		workBuf[p++] = number;
		workBuf[p++] = count;
		short start;
		short length;
		if (number == 1) {
			p = Util.arrayCopyNonAtomic(password, Common.OFFSET_ZERO, workBuf, p,
					LENGTH_PASSWORD);
			start = 0;
			length = dataLength < MAX_FIRST_SEGMENT_DATA ? dataLength : MAX_FIRST_SEGMENT_DATA;
		} else {
			start = (short) (MAX_FIRST_SEGMENT_DATA + (number - 2) * MAX_SEGMENT_DATA);
			length = (short) (dataLength - start);
			if (length > MAX_SEGMENT_DATA) {
				length = MAX_SEGMENT_DATA;
			}
		}
		p = Util.arrayCopyNonAtomic(workBuf, (short) (dataOffset + start), workBuf, p, length);

		short resultLength = EcdhUtil.encrypt(workBuf, segmentOffset,
				(short) (p - segmentOffset), coolSeedKey, Common.OFFSET_ZERO, destBuf,
				destOffset);
		clearWork(workBuf, workOffset, (short) (p - workOffset));
		return resultLength;
	}

	/**
	 * Compares the hash CoolSeed returned after the last segment with
	 * SHA-256(backup ID || data). The app knows neither, so it cannot make
	 * the hash of data it wrote itself. A mismatch keeps the export, so it
	 * can be written again after CoolSeed is reset.
	 */
	public static void confirmExport(byte[] buf, short offset, short length, byte[] workBuf,
			short workOffset) {
		checkExportStarted();
		if (length != Common.LENGTH_SHA256) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		Util.arrayCopyNonAtomic(backupId, Common.OFFSET_ZERO, workBuf, workOffset,
				LENGTH_BACKUP_ID);
		short hashOffset = (short) (workOffset + LENGTH_BACKUP_ID);
		hashOffset += buildData(workBuf, hashOffset);
		ShaUtil.SHA256(workBuf, workOffset, (short) (hashOffset - workOffset), workBuf,
				hashOffset);
		byte compare = Util.arrayCompare(buf, offset, workBuf, hashOffset,
				Common.LENGTH_SHA256);
		clearWork(workBuf, workOffset,
				(short) (hashOffset + Common.LENGTH_SHA256 - workOffset));
		if (compare != 0) {
			ISOException.throwIt(ErrorMessage.COOLSEED_HASH_MISMATCH);
		}
		coolSeedKeySet = false;
		clearExport();
	}

	/**
	 * Generates the key CoolSeed encrypts the segments for. It is used for
	 * one import only, and a new one drops the import in progress. The
	 * CoolSeed key has to be sent again after it, so the segments can only
	 * come from the CoolSeed of this restore.
	 *
	 * @return length of the public key in destBuf
	 */
	public static short newRestoreKey(byte[] destBuf, short destOffset) {
		CardInfo.checkWalletStatusNotEqual(Common.WALLET_CREATED);
		coolSeedKeySet = false;
		clearImport();
		restoreKeyPair.genKeyPair();
		restoreKeyValid = true;
		return ((ECPublicKey) restoreKeyPair.getPublic()).getW(destBuf, destOffset);
	}

	/**
	 * Decrypts and stores one segment. The wallet is written only after the
	 * last segment of the same backup, so an import cut off midway leaves
	 * the card without a wallet. A segment sent again is ignored, and a
	 * first segment of another backup starts over.
	 *
	 * CoolSeed encrypts the segments from its own key instead of an
	 * ephemeral one, so only the CoolSeed holding that private key gets the
	 * MAC right. The app knows the restore key and could otherwise encrypt
	 * a seed of its own.
	 */
	public static void importSegment(byte[] buf, short offset, short length, byte[] workBuf,
			short workOffset) {
		CardInfo.checkWalletStatusNotEqual(Common.WALLET_CREATED);
		if (!restoreKeyValid) {
			ISOException.throwIt(ErrorMessage.COOLSEED_RESTORE_KEY_NOT_SET);
		}
		if (!coolSeedKeySet) {
			ISOException.throwIt(ErrorMessage.COOLSEED_KEY_NOT_SET);
		}
		if (length < MIN_SEGMENT_CIPHER || length > MAX_SEGMENT_CIPHER) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		if (Util.arrayCompare(buf, offset, coolSeedKey, Common.OFFSET_ZERO,
				Common.LENGTH_PUBLICKEY) != 0) {
			ISOException.throwIt(ErrorMessage.COOLSEED_SENDER_INVALID);
		}
		short plainLength = EcdhUtil.decrypt(buf, offset, length, workBuf, workOffset,
				(ECPrivateKey) restoreKeyPair.getPrivate());
		short error = storeSegment(workBuf, workOffset, plainLength);
		clearWork(workBuf, workOffset, plainLength);
		if (error != 0) {
			ISOException.throwIt(error);
		}
	}

	// Returns 0, or the status word to throw once the plaintext is cleared
	private static short storeSegment(byte[] buf, short offset, short length) {
		if (length < LENGTH_SEGMENT_HEADER || buf[offset] != VERSION) {
			return ErrorMessage.COOLSEED_SEGMENT_INVALID;
		}
		byte number = buf[(short) (offset + OFFSET_SEGMENT_NUMBER)];
		byte count = buf[(short) (offset + OFFSET_SEGMENT_COUNT)];
		if (count < 1 || count > MAX_SEGMENT_COUNT || number < 1 || number > count) {
			return ErrorMessage.COOLSEED_SEGMENT_INVALID;
		}
		boolean sameBackup = importCount != 0 && Util.arrayCompare(buf, (short) (offset + 1),
				importId, Common.OFFSET_ZERO, LENGTH_BACKUP_ID) == 0;
		if (sameBackup && number < importNext) {
			return 0;
		}

		short dataOffset = (short) (offset + LENGTH_SEGMENT_HEADER);
		short maxData = MAX_SEGMENT_DATA;
		if (number == 1) {
			// The password is for CoolSeed only
			dataOffset += LENGTH_PASSWORD;
			maxData = MAX_FIRST_SEGMENT_DATA;
		} else if (!sameBackup || count != importCount || number != importNext) {
			return ErrorMessage.COOLSEED_SEGMENT_INVALID;
		}
		short dataLength = (short) (length - (dataOffset - offset));
		// CoolSeed cuts the data the same way as the export: every segment
		// but the last is full
		if (dataLength < 1 || dataLength > maxData
				|| (number < count && dataLength != maxData)) {
			return ErrorMessage.COOLSEED_SEGMENT_INVALID;
		}

		if (number == 1) {
			clearImport();
			Util.arrayCopy(buf, (short) (offset + 1), importId, Common.OFFSET_ZERO,
					LENGTH_BACKUP_ID);
			importCount = count;
		}
		Util.arrayCopy(buf, dataOffset, importData, importLength, dataLength);
		importLength += dataLength;
		importNext = (byte) (number + 1);
		if (number == count) {
			return finishImport();
		}
		return 0;
	}

	private static short finishImport() {
		short bip32Offset = -1;
		short bip32Ed25519Offset = -1;
		short p = 0;
		while (p < importLength) {
			if ((short) (importLength - p) < LENGTH_TLV_HEADER) {
				return failImport();
			}
			byte type = importData[p];
			short length = Util.getShort(importData, (short) (p + 1));
			p += LENGTH_TLV_HEADER;
			if (length < 0 || length > (short) (importLength - p)) {
				return failImport();
			}
			if (type == TYPE_BIP32) {
				if (length != Bip32.LENGTH_EXTENDKEY || bip32Offset >= 0) {
					return failImport();
				}
				bip32Offset = p;
			} else if (type == TYPE_BIP32ED25519) {
				if (length != Bip32Ed25519.LENGTH_EXTENDKEY || bip32Ed25519Offset >= 0) {
					return failImport();
				}
				bip32Ed25519Offset = p;
			}
			// Other types come from a newer firmware and are skipped
			p += length;
		}
		if (bip32Offset < 0) {
			return failImport();
		}

		Bip32.setSeed(importData, bip32Offset, Bip32.LENGTH_EXTENDKEY);
		if (bip32Ed25519Offset >= 0) {
			Bip32Ed25519.setMasterKey(importData, bip32Ed25519Offset,
					Bip32Ed25519.LENGTH_EXTENDKEY);
		} else {
			Bip32Ed25519.clearKey();
		}
		// Set last: a card cut off before this has no wallet
		CardInfo.setWalletStatus(Common.WALLET_CREATED);
		restoreKeyValid = false;
		coolSeedKeySet = false;
		clearImport();
		return 0;
	}

	private static short failImport() {
		clearImport();
		return ErrorMessage.COOLSEED_DATA_INVALID;
	}

	private static short buildData(byte[] destBuf, short destOffset) {
		short p = destOffset;
		destBuf[p++] = TYPE_BIP32;
		p = Util.setShort(destBuf, p, Bip32.LENGTH_EXTENDKEY);
		p += Bip32.backupData(destBuf, p);
		if (Bip32Ed25519.isInit() == (byte) 1) {
			destBuf[p++] = TYPE_BIP32ED25519;
			p = Util.setShort(destBuf, p, Bip32Ed25519.LENGTH_EXTENDKEY);
			p += Bip32Ed25519.backupData(destBuf, p);
		}
		return (short) (p - destOffset);
	}

	private static byte getSegmentCount(short dataLength) {
		if (dataLength <= MAX_FIRST_SEGMENT_DATA) {
			return 1;
		}
		return (byte) (1 + MathUtil.ceil((short) (dataLength - MAX_FIRST_SEGMENT_DATA),
				MAX_SEGMENT_DATA));
	}

	private static void checkExportStarted() {
		if (!exportStarted) {
			ISOException.throwIt(ErrorMessage.COOLSEED_EXPORT_NOT_STARTED);
		}
	}

	private static void clearExport() {
		exportStarted = false;
		Util.arrayFillNonAtomic(backupId, Common.OFFSET_ZERO, LENGTH_BACKUP_ID, (byte) 0);
		Util.arrayFillNonAtomic(password, Common.OFFSET_ZERO, LENGTH_PASSWORD, (byte) 0);
	}

	private static void clearImport() {
		importCount = 0;
		importNext = 0;
		Util.arrayFillNonAtomic(importData, Common.OFFSET_ZERO, importLength, (byte) 0);
		importLength = 0;
		Util.arrayFillNonAtomic(importId, Common.OFFSET_ZERO, LENGTH_BACKUP_ID, (byte) 0);
	}

	// The work buffer is persistent, so the seed must not stay in it
	private static void clearWork(byte[] workBuf, short workOffset, short length) {
		Util.arrayFillNonAtomic(workBuf, workOffset, length, (byte) 0);
	}
}
