/**
 * 
 */
package coolbitx;

import coolbitx.sio.StoreInterface;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.apdu.ExtendedLength;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public class Main extends Applet implements AppletEvent, ExtendedLength {

	private static final short ver = 337;

	private static boolean isInit = false;

	private byte[] longBuf;
	private byte[] destBuf;
	public static final short bufferLength = 3800;
	public static final short destBufLength = 3800;

	private byte[] signAesKey;

	static byte[] nonce;
	static byte[] workspace;
	private byte[] path;

	public static boolean factoryMode = false;
	public static boolean developMode = false;

	static final byte[] storeAid = { 'B', 'a', 'c', 'k', 'u', 'p', 'A', 'p',
			'p', 'l', 'e', 't', };
	static AID storeAppAid;
	static StoreInterface storeInterface;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		byte aidLength = bArray[bOffset++];
		short aidOffset = bOffset;
		bOffset += aidLength;

		byte controlLength = bArray[bOffset++];
		bOffset += controlLength;

		byte paraLength = bArray[bOffset++];
		short paraOffset = bOffset;
		new Main(bArray, paraOffset, paraLength).register(bArray, aidOffset,
				aidLength);
		storeAppAid = new AID(storeAid, (short) 0, (byte) storeAid.length);
		storeInterface = (StoreInterface) JCSystem
				.getAppletShareableInterfaceObject(storeAppAid, (byte) 0);
	}

	protected Main(byte[] bArray, short bOffset, short length) {
		if (length == 1) {
			byte argu = bArray[bOffset];
			if ((argu & 0x80) != 0) {
				factoryMode = true;
			}
			if ((argu & 0x40) != 0) {
				developMode = true;
			}
		}
		longBuf = new byte[bufferLength];
		destBuf = new byte[destBufLength];
		nonce = JCSystem.makeTransientByteArray(Common.LENGTH_NONCE,
				JCSystem.CLEAR_ON_DESELECT);
		workspace = JCSystem.makeTransientByteArray((short) 250,
				JCSystem.CLEAR_ON_DESELECT);
		signAesKey = JCSystem.makeTransientByteArray((short) 32,
				JCSystem.CLEAR_ON_DESELECT);
		path = new byte[102];
		WorkCenter.init();
		NonceUtil.init();
		SignUtil.init();
		Bip39.init();
		EcdhUtil.init();
		KeyUtil.init();
		Ripemd.init();
		CardInfo.init();
		FlowCounter.init();
		ScriptInterpreter.init();
		CardInfo.defaultSettings();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			if (!isInit) {
				Sha3.init();
				Sha2.init();
				Blake2b.init();
				Blake3.init();
				ShaUtil.init();
				KeyManager.init(); // must after ShaUtil
				Device.init();
				KeyStore.derive();
				isInit = true;
			}
			return;
		}
		byte[] apduBuf = apdu.getBuffer();
		if (apduBuf[ISO7816.OFFSET_CLA] != (byte) 0x80) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		if (!factoryMode) {
			boolean contactMedia = (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == 0;
			if (!contactMedia) {
				if (((apduBuf[ISO7816.OFFSET_INS] != (byte) 0xCA)
						&& (apduBuf[ISO7816.OFFSET_INS] != 0x52) && (apduBuf[ISO7816.OFFSET_INS] != 0x53))) {
					ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				}
			}
		}

		short dataLength = apdu.setIncomingAndReceive();
		short dataOffset = apdu.getOffsetCdata();
		short overallLength = apdu.getIncomingLength();

		byte[] buf = null;

		if (dataOffset == ISO7816.OFFSET_CDATA) {
			buf = apduBuf;
		} else if (dataOffset == ISO7816.OFFSET_EXT_CDATA) {
			buf = longBuf;
			Util.arrayFillNonAtomic(longBuf, Common.OFFSET_ZERO,
					(short) longBuf.length, (byte) 0);
			// Copy APDU & data length
			dataOffset = Util.arrayCopyNonAtomic(apduBuf, Common.OFFSET_ZERO,
					buf, Common.OFFSET_ZERO, (short) 7);
			// Copy data
			Util.arrayCopyNonAtomic(apduBuf, dataOffset, buf, dataOffset,
					dataLength);
			if (dataLength != overallLength) {
				short received = 0;
				do {
					received = apdu.receiveBytes((short) 0);
					Util.arrayCopyNonAtomic(apduBuf, (short) 0, buf,
							(short) (dataOffset + dataLength), received);
					dataLength += received;
				} while (received != 0);
			}
		} else {
			ISOException.throwIt((short) 0x6091);
		}
		short processLength;
		short destOffset = 0;
		short resultLength = 0;
		FlowCounter.reset();
		WorkCenter.reset();
		CardInfo.reset();

		try {
			switch (buf[ISO7816.OFFSET_INS]) {
			case (byte) 0x08:// verifyDfuSig
				ShaUtil.SHA256(buf, dataOffset, Common.LENGTH_SHA256, destBuf,
						destOffset);
				short signOffset = (short) (dataOffset + Common.LENGTH_SHA256);
				short signLength = (short) (dataLength - Common.LENGTH_SHA256);
				SignUtil.verifyData(destBuf, destOffset, Common.LENGTH_SHA256,
						buf, signOffset, signLength, KeyUtil.getPubKey(
								KeyStore.DFUPubKey, Common.OFFSET_ZERO));
				FlowCounter.checkValue((short) 2);
				break;
			case (byte) 0x10:// register
				if (buf[(short) (ISO7816.OFFSET_P1)] == 1) {
					dataLength = EcdhUtil.decrypt(buf, dataOffset, dataLength,
							buf, dataOffset,
							KeyStore.getPrivKey(KeyStore.KEY_SE));
				}
				if (dataLength != 99) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				if (Device.isFreezed()) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				if (Device.isFull()) {
					ISOException.throwIt(ISO7816.SW_FILE_FULL);
				}
				Device.setDevice(buf, dataOffset, destBuf, destOffset);
				resultLength = Common.LENGTH_APP_ID;
				break;
			case (byte) 0x14:// changePairingStatus
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				if (buf[(short) (ISO7816.OFFSET_P1)] == 0) {
					Device.setFreezed(false);
				} else if (buf[(short) (ISO7816.OFFSET_P1)] == 1) {
					Device.setFreezed(true);
				} else {
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
				break;
			case (byte) 0x18:// getSePairedDevices
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				resultLength = Device.getDeviceList(destBuf, destOffset);
				break;
			case (byte) 0x1A:// getPairPwd
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				processLength = Device.getPassword(destBuf, destOffset);
				resultLength = EcdhUtil.encrypt(destBuf, destOffset,
						processLength, destBuf, destOffset,
						Device.appPublicKeyList, Device
								.getAppPublicKeyByte(CardInfo
										.get(CardInfo.DEVICE)));
				break;
			case (byte) 0x1C: {
				// removeOtherSeDevices
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				byte removeDevice = Device.isRegistered(buf, dataOffset);
				if (removeDevice == -1) {
					ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				}
				if (CardInfo.get(CardInfo.DEVICE) == removeDevice) {
					ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
				}
				Device.removeDevice(removeDevice);
				break;
			}
			case (byte) 0x1E:// renameOwnSeDevice
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				Device.setName(buf, dataOffset, CardInfo.get(CardInfo.DEVICE));
				break;
			case (byte) 0x24:// createWallet
				CardInfo.checkWalletStatusNotEqual(Common.WALLET_CREATED);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				if (buf[(short) (dataOffset)] != 12
						&& buf[(short) (dataOffset)] != 18
						&& buf[(short) (dataOffset)] != 24) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				Bip39.createWallet(buf[(short) (dataOffset)]);
				CardInfo.setWalletStatus(Common.WALLET_DISPLAY);
				break;
			case (byte) 0x26:// readNumberMnemonic
				CardInfo.checkWalletStatusEqual(Common.WALLET_DISPLAY);
				resultLength = Bip39.getNumberMnemonic(destBuf, destOffset);
				break;
			case (byte) 0x2E: {
				// finishBackup
				CardInfo.checkWalletStatusEqual(Common.WALLET_DISPLAY);
				byte compareIfZero = Util.arrayCompare(buf, dataOffset,
						Bip39.zeroSum, Common.OFFSET_ZERO, (short) 4);
				byte compareResult = Util.arrayCompare(buf, dataOffset,
						Bip39.sum, Common.OFFSET_ZERO, (short) 4);
				if (compareIfZero == 0 || compareResult != 0) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				CardInfo.setWalletStatus(Common.WALLET_CALCULATION);
				break;
			}
			case (byte) 0x92:// readMnemonicIndex
				CardInfo.checkWalletStatusEqual(Common.WALLET_CALCULATION);
				resultLength = Bip39.getMnemonicIndex(destBuf, destOffset);
				break;
			case (byte) 0x22:// setSeed for mcu
				KeyManager.setSeed(buf, dataOffset, dataLength);
				CardInfo.setWalletStatus(Common.WALLET_CREATED);
				break;
			case (byte) 0x2A:// setSeed
				CardInfo.checkWalletStatusNotEqual(Common.WALLET_CREATED);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				dataLength = EcdhUtil.decrypt(buf, dataOffset, dataLength,
						destBuf, destOffset,
						KeyStore.getPrivKey(KeyStore.KEY_SE));// decrypt seed

				KeyManager.setSeed(destBuf, destOffset, dataLength);
				CardInfo.setWalletStatus(Common.WALLET_CREATED);
				break;
			case (byte) 0x2C:// authGetAccountExtendedKey
				CardInfo.checkWalletStatusEqual(Common.WALLET_CREATED);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				CardInfo.set(CardInfo.AUTH_GET_KEY, true);
				break;
			case (byte) 0x98:// readAccountExtendedKey
				if (CardInfo.is(CardInfo.AUTH_GET_KEY) == false) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				processLength = KeyManager.getDerivedPublicKey(buf, dataOffset,
						dataLength, true, buf, dataOffset);
				// encrypt account extended public key to buf
				resultLength = EcdhUtil.encrypt(buf, dataOffset, processLength,
						destBuf, destOffset, Device.appPublicKeyList, Device
								.getAppPublicKeyByte(CardInfo
										.get(CardInfo.DEVICE)));
				break;
			case (byte) 0x30:// clearTx
				CardInfo.set(CardInfo.AUTH_TX, false);
				CardInfo.set(CardInfo.EX_ADDR_EXIST, false);
				CardInfo.set(CardInfo.TRANSCATION_STATE, Common.STATE_NONE);
				break;
			case (byte) 0x34:// finishPrepare
				Check.checkState(Common.STATE_PREPARE);
				CardInfo.set(CardInfo.SIGN_AESKEY_VALID, false);
				CardInfo.set(CardInfo.TRANSCATION_STATE,
						Common.STATE_WAITING_AUTH);
				break;
			case (byte) 0x46:// getNewTxDetail
				Check.checkState(Common.STATE_WAITING_AUTH);
				resultLength = ScriptInterpreter.getTxDetail(destBuf,
						destOffset);
				break;
			case (byte) 0x38:// authorizeTx
				Check.checkState(Common.STATE_WAITING_AUTH);
				CardInfo.set(CardInfo.AUTH_TX, true);
				CardInfo.set(CardInfo.TRANSCATION_STATE, Common.STATE_TX);
				break;
			case (byte) 0x3A:// getTxKey
				Check.checkState(Common.STATE_TX);
				if (!CardInfo.is(CardInfo.AUTH_TX)) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				Util.arrayCopyNonAtomic(signAesKey, Common.OFFSET_ZERO,
						destBuf, destOffset, (short) 32);
				resultLength = 32;
				break;
			case (byte) 0x50:// hi
				if (dataLength != Common.LENGTH_APP_ID) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				if (Device.isRegistered(buf, dataOffset) == 0) {
					ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				}
				CardInfo.set(CardInfo.TRANSCATION_STATE, Common.STATE_PREPARE);
				break;
			case (byte) 0x52:// getVersion
			{
				Util.setShort(destBuf, destOffset, ver);
				if (buf[ISO7816.OFFSET_P1] == 0x12
						&& buf[ISO7816.OFFSET_P2] == 0x34) {
					byte isFactory = (byte) (Main.factoryMode ? 1 : 0);
					byte isDevelop = (byte) (Main.developMode ? 1 : 0);
					destBuf[0] = isFactory;
					destBuf[1] = isDevelop;
				}
				resultLength = 2;
				break;
			}
			case (byte) 0x53:// getSigningScriptVersion
				Util.setShort(destBuf, destOffset,
						ScriptInterpreter.scriptVersion);
				resultLength = 2;
				break;
			case (byte) 0x54:// getNonce
				NonceUtil.randomNonce(nonce, Common.OFFSET_ZERO,
						Common.LENGTH_NONCE);
				CardInfo.set(CardInfo.NONCE_ACTI, true);
				Util.arrayCopyNonAtomic(nonce, Common.OFFSET_ZERO, destBuf,
						destOffset, Common.LENGTH_NONCE);
				resultLength = Common.LENGTH_NONCE;
				break;
			case (byte) 0x56:// reset
				KeyManager.clearKey();
				Device.reset();
				ScriptInterpreter.reset();
				CardInfo.defaultSettings();
				break;
			case (byte) 0x60:// updateBalanceData
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				CardInfo.setBalance(buf, dataOffset, dataLength);
				break;
			case (byte) 0x62:// getBalanceData
				resultLength = CardInfo.getBalance(destBuf, destOffset);
				break;
			case (byte) 0x64:// changeDisplayType
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				CardInfo.setDisplayType(buf[(short) (ISO7816.OFFSET_P1)], false);
				break;
			case (byte) 0x66:// getCardInfo
			{
				// [Pair_Status(1B)][Freeze_Status(1B)][PairedRemainTimes(1B)]
				short ptr = Device.getCardInfo(destBuf, destOffset);
				// [Wallet_Status(1B)][Account_Digest(5B)][DisplayType(1B)][BIP32_ED25519_Is_Init(1B)][Account_Digest_20_Bytes(20B)]
				ptr = CardInfo.getCardInfo(destBuf, ptr);

				// prt = 31
				resultLength = ptr;
				break;
			}
			case (byte) 0x68:// echo
				destOffset = 0;
				Util.arrayCopyNonAtomic(buf, (short) 0, destBuf, destOffset,
						(short) (dataOffset + dataLength));
				resultLength = (short) (dataOffset + dataLength);
				break;
			case (byte) 0x6A:// updateIndexIdData
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				if (buf[(short) (ISO7816.OFFSET_P1)] == 0) {
					CardInfo.setIndexId(buf, dataOffset, (short) (4 * 3));
				} else {
					CardInfo.setIndexId(buf, dataOffset,
							(short) (buf[ISO7816.OFFSET_P1] * 3));
				}
				break;
			case (byte) 0x6C:// getIndexIdData
				if (buf[(short) (ISO7816.OFFSET_P1)] == 0) {
					resultLength = 4 * 3;
				} else {
					resultLength = (short) (buf[(short) (ISO7816.OFFSET_P1)] * 3);
				}
				CardInfo.getIndexId(destBuf, destOffset, resultLength);
				break;
			case (byte) 0x70:// delay
				for (byte i = 0; i < buf[ISO7816.OFFSET_P1]; i++) {
					ShaUtil.SHA512(buf, dataOffset, dataLength, destBuf,
							destOffset);
				}
				if (buf[(short) (ISO7816.OFFSET_P2)] != 0) {
					destOffset = 0;
					resultLength = (short) (dataOffset + dataLength);
				}
				break;
			case (byte) 0x80:// backupRegisterData
				// need long buf to store data
				buf = longBuf;
				Util.arrayFillNonAtomic(longBuf, Common.OFFSET_ZERO,
						(short) longBuf.length, (byte) 0);
				CardInfo.checkWalletStatusEqual(Common.WALLET_CREATED);
				if (storeInterface.isDataBackup()) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				short length = BackupController.backup(buf, dataOffset);
				length = EcdhUtil.encryptAES(buf, dataOffset, length, buf,
						dataOffset, KeyStore.getAESKey(KeyStore.KEY_SE));
				// add checksum
				length += ShaUtil.SHA256(buf, dataOffset, length, buf,
						(short) (dataOffset + length));
				for (byte seqNo = 0;; seqNo++) {
					if (length > 250) {
						Util.arrayCopyNonAtomic(buf,
								(short) (dataOffset + seqNo * 250),
								APDU.getCurrentAPDUBuffer(), (short) 0,
								(short) (250));
						storeInterface.setData(APDU.getCurrentAPDUBuffer(),
								(short) 0, (short) 250, seqNo, false);
						length -= 250;
					} else {
						Util.arrayCopyNonAtomic(buf,
								(short) (dataOffset + seqNo * 250),
								APDU.getCurrentAPDUBuffer(), (short) 0, length);
						storeInterface.setData(APDU.getCurrentAPDUBuffer(),
								(short) 0, length, seqNo, true);
						break;
					}
				}
				break;
			case (byte) 0x82:// recoverRegisterData
				buf = longBuf;
				Util.arrayFillNonAtomic(longBuf, Common.OFFSET_ZERO,
						(short) longBuf.length, (byte) 0);
				if (storeInterface.isDataBackup()) {
					short dataLen = storeInterface.getDataLength();
					short totalSeq = MathUtil.ceil(dataLen, (short) 250);
					short totalLen = 0;
					for (byte seqNo = 0; seqNo < totalSeq; seqNo++) {
						processLength = storeInterface.getData(
								APDU.getCurrentAPDUBuffer(), (short) 0, seqNo);
						Util.arrayCopyNonAtomic(APDU.getCurrentAPDUBuffer(),
								(short) 0, buf,
								(short) (dataOffset + totalLen), processLength);
						totalLen += processLength;
					}
					resultLength = EcdhUtil.decryptAES(buf, dataOffset,
							totalLen, buf, dataOffset,
							KeyStore.getAESKey(KeyStore.KEY_SE));
					BackupController.recover(buf, dataOffset, resultLength);
					storeInterface.reset();
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				resultLength = 0;
				break;
			case (byte) 0x84:// resetRegisterData
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				storeInterface.reset();
				break;
			case (byte) 0x86:// getRegisterDataStatus
				if (!storeInterface.isDataBackup()) {
					destBuf[(short) (destOffset)] = 0;
				} else {
					destBuf[(short) (destOffset)] = 1;
				}
				resultLength = 1;
				break;
			case (byte) 0xAC:// setScript
				ScriptInterpreter.setScript(buf, dataOffset, dataLength);
				break;
			case (byte) 0xA2:// txPrepScript
				// Check.checkState(Common.STATE_PREPARE);
				CardInfo.set(CardInfo.TRANSCATION_STATE, Common.STATE_PREPARE);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				if (buf[ISO7816.OFFSET_P1] == 0) {
					short pathLength = buf[dataOffset];
					Util.arrayCopyNonAtomic(buf, dataOffset, path,
							Common.OFFSET_ZERO, (short) (pathLength + 1));

					dataOffset = (short) (dataOffset + 1 + pathLength);
					dataLength = (short) (dataLength - 1 - pathLength);
				}
				resultLength = ScriptInterpreter.setArgument(buf, dataOffset,
						dataLength, buf[ISO7816.OFFSET_P1],
						buf[ISO7816.OFFSET_P2]);

				if (resultLength != 0) {
					ScriptInterpreter.execute();
					short pathLength = path[Common.OFFSET_ZERO];
					processLength = ScriptInterpreter.signTransaction(path,
							Common.OFFSET_ONE, pathLength, buf, dataOffset);

					// encrypt sign result for APP
					if (!CardInfo.is(CardInfo.SIGN_AESKEY_VALID)) {
						NonceUtil.randomNonce(signAesKey, Common.OFFSET_ZERO,
								(short) 32);
						CardInfo.set(CardInfo.SIGN_AESKEY_VALID, true);
					}
					resultLength = EcdhUtil.encryptAES(buf, dataOffset,
							processLength, destBuf, destOffset,
							KeyUtil.getAesKey(signAesKey, Common.OFFSET_ZERO));
				}
				break;
			case (byte) 0xA4:// txPrepUTXO
			{
				Check.checkState(Common.STATE_PREPARE);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				short pathLength = buf[dataOffset];
				processLength = ScriptInterpreter.signUtxoTransaction(buf,
						(short) (dataOffset + 1 + pathLength), buf,
						(short) (dataOffset + 1), pathLength,
						buf[ISO7816.OFFSET_P1], buf, dataOffset);
				// encrypt sign result for APP
				if (!CardInfo.is(CardInfo.SIGN_AESKEY_VALID)) {
					NonceUtil.randomNonce(signAesKey, Common.OFFSET_ZERO,
							(short) 32);
					CardInfo.set(CardInfo.SIGN_AESKEY_VALID, true);
				}
				resultLength = EcdhUtil.encryptAES(buf, dataOffset,
						processLength, destBuf, destOffset,
						KeyUtil.getAesKey(signAesKey, Common.OFFSET_ZERO));
				break;
			}
			case (byte) 0xA6:// getTransaction
				resultLength = ScriptInterpreter.getTransaction(destBuf,
						destOffset);
				break;
			case (byte) 0xA8: {
				// txPrepSegmentData
				Check.checkState(Common.STATE_PREPARE);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				// Only update transaction when first chunk is reaching.
				boolean shouldUpdateTransaction = buf[ISO7816.OFFSET_P1] == 0;
				short pathLength = path[Common.OFFSET_ZERO];
				processLength = ScriptInterpreter.signSegmentData(buf,
						dataOffset, dataLength, path, Common.OFFSET_ONE,
						pathLength, buf, dataOffset, shouldUpdateTransaction);
				if (processLength != 0) {
					if (!CardInfo.is(CardInfo.SIGN_AESKEY_VALID)) {
						NonceUtil.randomNonce(signAesKey, Common.OFFSET_ZERO,
								(short) 32);
						CardInfo.set(CardInfo.SIGN_AESKEY_VALID, true);
					}
					resultLength = EcdhUtil.encryptAES(buf, dataOffset,
							processLength, destBuf, destOffset,
							KeyUtil.getAesKey(signAesKey, Common.OFFSET_ZERO));
				}
				break;
			}
			case (byte) 0xAA: {
				// txPrepUTXOSegmentData
				Check.checkState(Common.STATE_PREPARE);
				Check.verifyCommand(buf, (short) 0, dataOffset, dataLength);
				dataLength -= 92;
				// Only update transaction when first chunk is reaching.
				boolean shouldUpdateTransaction = buf[ISO7816.OFFSET_P1] == 0;
				short pathLength = buf[dataOffset];
				Util.arrayCopyNonAtomic(buf, dataOffset, path,
						Common.OFFSET_ZERO, (short) (pathLength + 1));
				dataOffset = (short) (dataOffset + 1 + pathLength);
				dataLength = (short) (dataLength - 1 - pathLength);

				processLength = ScriptInterpreter.signSegmentData(buf,
						dataOffset, dataLength, path, Common.OFFSET_ONE,
						pathLength, buf, dataOffset, shouldUpdateTransaction);
				if (processLength != 0) {
					if (!CardInfo.is(CardInfo.SIGN_AESKEY_VALID)) {
						NonceUtil.randomNonce(signAesKey, Common.OFFSET_ZERO,
								(short) 32);
						CardInfo.set(CardInfo.SIGN_AESKEY_VALID, true);
					}
					resultLength = EcdhUtil.encryptAES(buf, dataOffset,
							processLength, destBuf, destOffset,
							KeyUtil.getAesKey(signAesKey, Common.OFFSET_ZERO));
				}
				break;
			}
			case (byte) 0xCA:// Get card id from storage applet
				resultLength = storeInterface.getCardId(
						APDU.getCurrentAPDUBuffer(), (short) 0);
				Util.arrayCopyNonAtomic(APDU.getCurrentAPDUBuffer(), (short) 0,
						destBuf, destOffset, resultLength);
				break;
			case (byte) 0xE0: {
				short secretLength = Util.getShort(buf, dataOffset);
				short requireShares = (short) (buf[ISO7816.OFFSET_P1] & 0x00ff);
				short totalShares = (short) (buf[ISO7816.OFFSET_P2] & 0x00ff);
				resultLength = Shamir.separate(buf, (short) (dataOffset + 2),
						secretLength, totalShares, requireShares, destBuf,
						destOffset);
				break;
			}
			case (byte) 0xE2: {
				short requireShares = (short) (buf[ISO7816.OFFSET_P1] & 0x00ff);
				resultLength = Shamir.derive(buf, dataOffset, dataLength,
						requireShares, destBuf, destOffset);
				break;
			}
			case (byte) 0xFF:
				JCSystem.requestObjectDeletion();
				break;
			default:
				// good practice: If you don't know the INStruction, say so:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} catch (CryptoException ce) {
			ISOException.throwIt((short) (ISO7816.SW_UNKNOWN | ce.getReason()));
		}
		apdu.setOutgoing();
		apdu.setOutgoingLength(resultLength);
		apdu.sendBytesLong(destBuf, destOffset, resultLength);
	}

	public final void uninstall() {
		// Ed25519.uninit();
		ScriptInterpreter.uninit();
		KeyManager.uninit();
		Bip39.uninit();
		Device.uninit();
		EcdhUtil.uninit();
		KeyUtil.uninit();
		NonceUtil.uninit();
		Sha3.uninit();
		Sha2.uninit();
		Blake2b.uninit();
		Blake3.uninit();
		ShaUtil.uninit();
		SignUtil.uninit();
		Ripemd.uninit();
		CardInfo.uninit();
		WorkCenter.uninit();
		FlowCounter.uninit();
		uninit();
		JCSystem.requestObjectDeletion();
	}

	public final void uninit() {
		longBuf = null;
		destBuf = null;
		nonce = null;
		workspace = null;
		signAesKey = null;
		path = null;
		storeAppAid = null;
		storeInterface = null;
	}
}
