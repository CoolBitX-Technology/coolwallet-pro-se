package javacardx.crypto;

import com.licel.jcardsim.crypto.AsymmetricCipherImpl;
import javacard.security.CryptoException;
import javacard.security.Key;

/**
 * Wrapper around jcardsim's AsymmetricCipherImpl that always left-pads the
 * RSA NOPAD output with leading zeros to the full block size (I2OSP, RFC 8017 §4.1).
 *
 * jcardsim's processBlock returns only the significant bytes of the RSA result
 * (no leading zeros), but JavaCard spec requires the output to always fill the
 * full block size. Without this fix, inv(k) is wrong whenever k^(n-2) mod pq
 * has a leading zero byte.
 */
class PaddedAsymmetricCipher extends Cipher {

    private final AsymmetricCipherImpl delegate;

    PaddedAsymmetricCipher(byte algorithm) {
        this.delegate = new AsymmetricCipherImpl(algorithm);
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        delegate.init(theKey, theMode);
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen)
            throws CryptoException {
        delegate.init(theKey, theMode, bArray, bOff, bLen);
    }

    @Override
    public byte getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public short update(byte[] inBuff, short inOffset, short inLen, byte[] outBuff, short outOffset)
            throws CryptoException {
        return delegate.update(inBuff, inOffset, inLen, outBuff, outOffset);
    }

    /**
     * Performs RSA block cipher and left-pads the output with leading zeros to inLen bytes.
     *
     * This compensates for BouncyCastle processBlock() returning fewer bytes
     * than the block size when the result has leading zero bytes.
     */
    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLen, byte[] outBuff, short outOffset)
            throws CryptoException {
        // Use a temporary buffer so in-place callers (inBuff == outBuff) work correctly
        byte[] temp = new byte[inLen];
        short written = delegate.doFinal(inBuff, inOffset, inLen, temp, (short) 0);
        short pad = (short) (inLen - written);
        // Zero-fill leading bytes, then copy result right-aligned
        for (short i = 0; i < pad; i++) {
            outBuff[(short) (outOffset + i)] = 0;
        }
        System.arraycopy(temp, 0, outBuff, outOffset + pad, written);
        return inLen;
    }
}
