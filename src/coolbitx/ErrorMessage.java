package coolbitx;

public class ErrorMessage {
	// ------------ DeviceManager.java
	/*
	 * The card does not recognize any devices.
	 */
	public static final short _6fff = 0x6fff;
	/*
	 * Backup date checksum invalid
	 */
	public static final short _6A00 = 0x6A00;

	// ------------ Bip32.java
	/*
	 * The path uses an unsupported scheme in the `getDerivedPublicKey` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, CURVE25519, or
	 * SLIP0010.
	 */
	public static final short _6D60 = 0x6D60;
	/*
	 * The signType uses an unsupported type in the `deriveKeyAndSign` method;
	 * it should be limited to SIGN_SECP256K1, SIGN_ED25519, SIGN_CURVE25519, or
	 * SIGN_SCHNORR.
	 */
	public static final short _6D61 = 0x6D61;
	/*
	 * The path length is incorrect.
	 */
	public static final short _6D63 = 0x6D63;
	/*
	 * The path uses an unsupported scheme in the `getDerivedKeyByPath` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, or SLIP0010.
	 */
	public static final short _6D65 = 0x6D65;
	/*
	 * The SLIP0010 path contains non-hardened index
	 */
	public static final short _6D6C = 0x6D6C;

	// ------------ Bip32Ed25519
	/*
	 * The path length is incorrect.
	 */
	public static final short _6D62 = 0x6D62;
	/*
	 * The master key has not been initialized.
	 */
	public static final short _6D64 = 0x6D64;
	/*
	 * The signType uses an unsupported type in the `deriveKeyAndSign` method;
	 * it should be limited toSIGN_BIP32ED25519.
	 */
	public static final short _6D66 = 0x6D66;

	// ------------ KeyManager
	/*
	 * The signType uses an unsupported type in the `deriveKeyAndSign` method;
	 * it should be limited to SIGN_SECP256K1, SIGN_ED25519, SIGN_CURVE25519,
	 * SIGN_SCHNORR, or SIGN_BIP32ED25519.
	 */
	public static final short _6D67 = 0x6D67;
	/*
	 * The path uses an unsupported scheme in the `getDerivedPublicKey` method;
	 * it should be limited to BIP32, BIP32EDDSA, BIP340, CURVE25519, SLIP0010,
	 * or BIP32ED25519.
	 */
	public static final short _6D68 = 0x6D68;

	// ------------ UniqueImplement
	public static final short _6D70 = 0x6D70;
	public static final short _6D71 = 0x6D71;

	// ------------ KeyGenerate
	/*
	 * Invalid cardType parameter; it should be either CARD_PRO or CARD_LITE.
	 */
	public static final short _6EA0 = 0x6EA0;
	/*
	 * Invalid keyType parameter; it should be either KEY_SE_ENC or KEY_SE_TRANS.
	 */
	public static final short _6EA1 = 0x6EA1;

}
