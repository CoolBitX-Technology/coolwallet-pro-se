package coolbitx.sio;

import javacard.framework.Shareable;

public interface GenuineKeyI extends Shareable {

	public short getPublicKey(byte[] destBuf, short destOffset);

	public void setSecretUpdate(byte[] cipherBuf, short cipherOffset,
			short cipherLength);

	public void setSecretFinal();

	public short getInstallType();

	public short getCardName(byte[] destBuf, short destOffset);

	public short getGenuinePrivateKey(byte[] destBuf, short destOffset);

	public short getGenuineChainCode(byte[] destBuf, short destOffset);

	public short getSecret(short srcOffset, short length, byte[] destBuf,
			short destOffset);
}
