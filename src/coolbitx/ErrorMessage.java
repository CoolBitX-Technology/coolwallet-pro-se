package coolbitx;

/*
 * Status words thrown by this applet.
 *
 * Layout: SW1 = module, high nibble of SW2 = file / feature, low nibble of
 * SW2 = specific error. Each feature therefore has 16 slots, and every module
 * keeps spare feature blocks for future use.
 *
 * SW1  Module                            Must not use (ISO 7816-4 / project)
 * 69   Command auth / device / backup    6900, 6981-698F
 * 6A   ScriptInterpreter                 6A80-6A8F
 * 6B   NumberUtil encoding               6B00
 * 6D   Key derivation / crypto           6D00
 * 6E   Data parsers (RLP, ...)           6E00
 * 6F   System internal state             6F00, 6F01-6F0F (CryptoException)
 * 65, 67, 68: spare modules              6500/6581, 6700, 6800/6881-6884,
 *                                        6789 (sio StoreApplet)
 *
 * Never use SW1 = 60 (T=0 NULL procedure byte), 61 / 6C (SW2 is read as a
 * length by the host), or 62 / 63 / 64 / 66 (warnings / ISO reserved).
 *
 * The crypto sources from coolwallet-pro-se-crypto throw their own codes from
 * CryptoError (6D0x, 6D2x, 6D4x), so they do not depend on this class.
 *
 * Main.process() maps an uncaught CryptoException to 0x6F00 | reason, so
 * 0x6F01-0x6F0F are taken by CryptoException reasons (RlpDecoder uses 6).
 */
public class ErrorMessage {

	// ================ 0x69 Command auth / device / backup ================

	// ------------ 0x690x Check.verifyCommand
	/* Command data is shorter than appId(20B) + signature(72B). */
	public static final short CMD_DATA_TOO_SHORT = 0x6901;
	/* Nonce has not been activated before the signed command. */
	public static final short CMD_NONCE_NOT_ACTIVATED = 0x6902;
	/* The appId in the command is not a registered device. */
	public static final short CMD_APP_NOT_REGISTERED = 0x6903;
	/* The command signature does not verify against the app public key. */
	public static final short CMD_SIGNATURE_INVALID = 0x6904;

	// ------------ 0x691x DeviceManager
	/* PIN length exceeds the maximum PIN size. */
	public static final short DEVICE_PIN_TOO_LONG = 0x6910;
	/* Device index is larger than DEVICE_NUM. */
	public static final short DEVICE_INDEX_OUT_OF_RANGE = 0x6911;
	/* The card does not recognize any current device. */
	public static final short DEVICE_NO_CURRENT_DEVICE = 0x6912;
	/* The card is not paired with any device. */
	public static final short DEVICE_NOT_PAIRED = 0x6913;
	/* The PIN is frozen. */
	public static final short DEVICE_PIN_FROZEN = 0x6914;
	/* The old PIN does not match; one try is consumed. */
	public static final short DEVICE_PIN_WRONG = 0x6915;
	/* The new PIN is not 6-8 BCD digits left-padded with F nibbles. */
	public static final short DEVICE_PIN_FORMAT_INVALID = 0x6916;
	/* The new PIN is the same as the old PIN. */
	public static final short DEVICE_PIN_SAME_AS_OLD = 0x6917;

	// ------------ 0x692x BackupController
	/* Backup data contains an unknown key type. */
	public static final short BACKUP_UNKNOWN_KEY_TYPE = 0x6920;

	// ================ 0x6A ScriptInterpreter ================

	// ------------ 0x6A0x Script loading / header / command
	/* Script signature does not verify against the script public key. */
	public static final short SCRIPT_SIGNATURE_INVALID = 0x6A01;
	/* Script header length is less than 3. */
	public static final short SCRIPT_HEADER_TOO_SHORT = 0x6A02;
	/* Script version is newer than the supported version. */
	public static final short SCRIPT_VERSION_UNSUPPORTED = 0x6A03;
	/* Unknown script command. */
	public static final short SCRIPT_UNKNOWN_COMMAND = 0x6A04;
	/* Script executed the abort command (0xFF). */
	public static final short SCRIPT_ABORT = 0x6A05;

	// ------------ 0x6A1x Argument sources
	/* Unsupported data source in getDataBuffer / getDataArray. */
	public static final short SCRIPT_INVALID_DATA_SOURCE = 0x6A10;
	/* Unsupported integer source. */
	public static final short SCRIPT_INVALID_INT_SOURCE = 0x6A11;
	/* Unsupported charset. */
	public static final short SCRIPT_INVALID_CHARSET = 0x6A12;
	/* Constant copy switch (0xC1) index is out of range. */
	public static final short SCRIPT_CASE_INDEX_OUT_OF_RANGE = 0x6A13;
	/* bufferInt data length is neither 1 nor 2. */
	public static final short SCRIPT_BUFFER_INT_LENGTH_INVALID = 0x6A14;
	/* Unsupported signature verification mode. */
	public static final short SCRIPT_VERIFY_MODE_INVALID = 0x6A15;
	/* Wrap page (0xD2) argument is out of range (argInt0 0-8, argInt1 0-7). */
	public static final short SCRIPT_WRAP_PAGE_OUT_OF_RANGE = 0x6A16;

	// ------------ 0x6A2x Hash / checksum types
	public static final short SCRIPT_INVALID_HASH_TYPE = 0x6A20;
	public static final short SCRIPT_INVALID_UPDATE_HASH_TYPE = 0x6A21;
	public static final short SCRIPT_INVALID_PERSONAL_HASH_TYPE = 0x6A22;
	public static final short SCRIPT_INVALID_CHECKSUM_TYPE = 0x6A23;
	public static final short SCRIPT_INVALID_TAGGED_HASH_TYPE = 0x6A24;

	// ------------ 0x6A3x Data format
	/* String contains a non-printable character or a double quote. */
	public static final short SCRIPT_INVALID_STRING_CHAR = 0x6A30;
	/* Amount with odd digit count has a non-zero leading nibble. */
	public static final short SCRIPT_AMOUNT_ODD_DIGIT = 0x6A31;
	/* Amount exceeds the displayable integer + decimal length. */
	public static final short SCRIPT_AMOUNT_OVERFLOW = 0x6A32;
	/* Unsupported protobuf wire type. */
	public static final short SCRIPT_PROTOBUF_WIRE_TYPE_UNSUPPORTED = 0x6A33;
	/* Placeholder data length is neither 0 nor 4. */
	public static final short SCRIPT_PLACEHOLDER_LENGTH_INVALID = 0x6A34;
	/* Bit array length is not a multiple of 8. */
	public static final short SCRIPT_BIT_ARRAY_LENGTH_INVALID = 0x6A35;
	/* Unsupported message pack type. */
	public static final short SCRIPT_MSGPACK_TYPE_INVALID = 0x6A36;
	/* Message pack element is used outside of an array. */
	public static final short SCRIPT_MSGPACK_NOT_IN_ARRAY = 0x6A37;

	// ------------ 0x6A4x Array stack
	/* Array nesting exceeds arrayMax. */
	public static final short SCRIPT_ARRAY_TOO_DEEP = 0x6A40;
	/* Array end without a matching array start. */
	public static final short SCRIPT_ARRAY_UNDERFLOW = 0x6A41;
	/* Array length is negative. */
	public static final short SCRIPT_ARRAY_LENGTH_NEGATIVE = 0x6A42;

	// ------------ 0x6A9x Signing state
	/* Signing is requested before the script has been executed. */
	public static final short SCRIPT_NOT_EXECUTED = 0x6A90;
	/* Path is too short to contain a coin type. */
	public static final short SCRIPT_PATH_TOO_SHORT = 0x6A91;
	/* Coin type in the path does not match the script. */
	public static final short SCRIPT_COIN_TYPE_MISMATCH = 0x6A92;
	/* Remaining data type does not match the UTXO sign type. */
	public static final short SCRIPT_UTXO_REMAIN_DATA_TYPE_INVALID = 0x6A93;
	/* Unsupported UTXO sign type. */
	public static final short SCRIPT_UTXO_SIGN_TYPE_UNSUPPORTED = 0x6A94;
	/* Unsupported UTXO script type in updateBtcScript. */
	public static final short SCRIPT_UTXO_SCRIPT_TYPE_UNSUPPORTED = 0x6A95;

	// ================ 0x6B NumberUtil ================

	// ------------ 0x6B0x Base conversion / arithmetic
	/* Input character is not in the source charset. */
	public static final short NUM_CHAR_NOT_IN_CHARSET = 0x6B01;
	/* Input is longer than the output buffer. */
	public static final short NUM_OUTPUT_TOO_SHORT = 0x6B02;
	/* Arithmetic result overflows the buffer. */
	public static final short NUM_OVERFLOW = 0x6B03;
	/* Left justify 8-to-5 requires charset 256 -> 32. */
	public static final short NUM_LEFT_JUSTIFY_CHARSET_INVALID = 0x6B04;

	// ------------ 0x6B1x Message pack
	public static final short MSGPACK_INT_TOO_LONG = 0x6B10;
	public static final short MSGPACK_STRING_TOO_LONG = 0x6B11;
	public static final short MSGPACK_BOOLEAN_LENGTH_INVALID = 0x6B12;
	public static final short MSGPACK_BINARY_TOO_LONG = 0x6B13;
	public static final short MSGPACK_ARRAY_TOO_LONG = 0x6B14;
	public static final short MSGPACK_MAP_TOO_LONG = 0x6B15;
	public static final short MSGPACK_TYPE_INVALID = 0x6B16;

	// ================ 0x6D Key derivation / crypto ================

	// 0x6D0x Blake2b, 0x6D2x Bip32Ed25519 and 0x6D4x KeyGenerate are defined in
	// CryptoError (coolwallet-pro-se-crypto); do not use those blocks here.

	// ------------ 0x6D1x Bip32
	/*
	 * The path uses an unsupported scheme in the `getDerivedPublicKey` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, CURVE25519, or
	 * SLIP0010.
	 */
	public static final short BIP32_PUBKEY_UNSUPPORTED_SCHEME = 0x6D10;
	/*
	 * The signType uses an unsupported type in the `deriveKeyAndSign` method;
	 * it should be limited to SIGN_SECP256K1, SIGN_ED25519, SIGN_CURVE25519, or
	 * SIGN_SCHNORR.
	 */
	public static final short BIP32_SIGN_TYPE_UNSUPPORTED = 0x6D11;
	/* The path length is incorrect. */
	public static final short BIP32_PATH_LENGTH_INVALID = 0x6D12;
	/*
	 * The path uses an unsupported scheme in the `getDerivedKeyByPath` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, or SLIP0010.
	 */
	public static final short BIP32_DERIVE_UNSUPPORTED_SCHEME = 0x6D13;
	/* The SLIP0010 path contains a non-hardened index. */
	public static final short BIP32_SLIP0010_NON_HARDENED = 0x6D14;
	/* Parent public key length is incorrect. */
	public static final short BIP32_PUBKEY_LENGTH_INVALID = 0x6D15;
	/* Hardened index cannot be derived from a public key. */
	public static final short BIP32_PUBLIC_DERIVE_HARDENED = 0x6D16;

	// ------------ 0x6D3x KeyManager
	/*
	 * The signType uses an unsupported type in the `deriveKeyAndSign` method;
	 * it should be limited to SIGN_SECP256K1, SIGN_ED25519, SIGN_CURVE25519,
	 * SIGN_SCHNORR, or SIGN_BIP32ED25519.
	 */
	public static final short KEY_SIGN_TYPE_UNSUPPORTED = 0x6D30;
	/*
	 * The path uses an unsupported scheme in the `getDerivedPublicKey` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, CURVE25519, SLIP0010,
	 * or BIP32ED25519.
	 */
	public static final short KEY_PUBKEY_UNSUPPORTED_SCHEME = 0x6D31;

	// ------------ 0x6D5x EcdhUtil
	/* ECDH shared-secret decryption failed. */
	public static final short ECDH_DECRYPT_FAILED = 0x6D50;

	// ================ 0x6E Data parsers ================

	// ------------ 0x6E1x RlpDataParser
	/* Child element has an invalid RLP prefix. */
	public static final short RLP_INVALID_CHILD_PREFIX = 0x6E10;
	/* Path index is out of the short list range. */
	public static final short RLP_INDEX_OUT_OF_RANGE = 0x6E11;
	/* Long list length exceeds the input data. */
	public static final short RLP_LIST_LENGTH_EXCEEDED = 0x6E12;
	/* Path index is out of the long list range. */
	public static final short RLP_LONG_LIST_INDEX_OUT_OF_RANGE = 0x6E14;
	/* Path goes through an element that is not a list. */
	public static final short RLP_NOT_A_LIST = 0x6E15;
	/* Element length is larger than 32767. */
	public static final short RLP_LENGTH_TOO_LARGE = 0x6E16;
	/* Final element has an invalid RLP prefix. */
	public static final short RLP_INVALID_FINAL_PREFIX = 0x6E17;

	// ================ 0x6F System internal state ================

	// ------------ 0x6F1x FlowCounter
	/* Flow counter does not match the expected step. */
	public static final short FLOW_COUNTER_MISMATCH = 0x6F10;
	// 0x6F11-0x6F15 are reserved: they held the CardInfo / WorkCenter / Main
	// codes below before those were split by file; do not reuse them.

	// ------------ 0x6F2x (reserved)
	// 0x6F20-0x6F24 belonged to Check, which now throws only the error code
	// its caller passes in; do not reuse them for other errors.

	// ------------ 0x6F3x CardInfo
	/* CardInfo boolean state is neither TRUE16 nor FALSE16. */
	public static final short CARD_INFO_STATE_CORRUPTED = 0x6F30;

	// ------------ 0x6F4x WorkCenter
	/* Unknown workspace id. */
	public static final short WORKSPACE_INVALID = 0x6F40;
	/* Workspace offset requested before a workspace is assigned. */
	public static final short WORKSPACE_NOT_ASSIGNED = 0x6F41;
	/* APDU workspace is not released at the end of a command. */
	public static final short WORKSPACE_APDU_NOT_EMPTY = 0x6F42;

	// ------------ 0x6F5x Main
	/* APDU data offset is neither short nor extended format. */
	public static final short APDU_DATA_OFFSET_INVALID = 0x6F50;

}
