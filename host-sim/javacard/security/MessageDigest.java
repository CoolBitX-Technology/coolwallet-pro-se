package javacard.security;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Shadow of jcardsim's javacard.security.MessageDigest.
 *
 * Fix: jcardsim's MessageDigest$OneShot.open() is a stub that returns null
 * (bytecode: aconst_null; areturn). This causes NullPointerException when
 * StoreObject.setData() calls dig.doFinal() during backup checksum verification.
 *
 * This shadow provides a working OneShot implementation backed by java.security.MessageDigest,
 * while keeping the abstract outer class compatible so that jcardsim's MessageDigestImpl
 * (which extends InitializedMessageDigest extends this class) still loads correctly.
 */
public abstract class MessageDigest {

    public static final byte ALG_NULL      = 0;
    public static final byte ALG_SHA       = 1;
    public static final byte ALG_MD5       = 2;
    public static final byte ALG_RIPEMD160 = 3;
    public static final byte ALG_SHA_256   = 4;
    public static final byte ALG_SHA_384   = 5;
    public static final byte ALG_SHA_512   = 6;
    public static final byte ALG_SHA_224   = 7;
    public static final byte ALG_SHA3_224  = 8;
    public static final byte ALG_SHA3_256  = 9;
    public static final byte ALG_SHA3_384  = 10;
    public static final byte ALG_SHA3_512  = 11;

    public static final byte LENGTH_MD5       = 16;
    public static final byte LENGTH_RIPEMD160 = 20;
    public static final byte LENGTH_SHA       = 20;
    public static final byte LENGTH_SHA_224   = 28;
    public static final byte LENGTH_SHA_256   = 32;
    public static final byte LENGTH_SHA_384   = 48;
    public static final byte LENGTH_SHA_512   = 64;
    public static final byte LENGTH_SHA3_224  = 28;
    public static final byte LENGTH_SHA3_256  = 32;
    public static final byte LENGTH_SHA3_384  = 48;
    public static final byte LENGTH_SHA3_512  = 64;

    protected MessageDigest() {}

    public abstract byte getAlgorithm();
    public abstract byte getLength();
    public abstract short doFinal(byte[] inBuf, short inOff, short inLen,
            byte[] outBuf, short outOff) throws CryptoException;
    public abstract void update(byte[] inBuf, short inOff, short inLen)
            throws CryptoException;
    public abstract void reset();

    public static final MessageDigest getInstance(byte algorithm,
            boolean externalAccess) throws CryptoException {
        // Delegate to jcardsim's concrete implementation which still extends this class
        // at runtime (jcardsim's InitializedMessageDigest → this class).
        // Instantiate via reflection to avoid a compile-time dependency loop.
        try {
            Class<?> implClass = Class.forName(
                    "com.licel.jcardsim.crypto.MessageDigestImpl");
            return (MessageDigest) implClass
                    .getConstructor(byte.class)
                    .newInstance(algorithm);
        } catch (Exception e) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
            return null;
        }
    }

    public static final InitializedMessageDigest getInitializedMessageDigestInstance(
            byte algorithm, boolean externalAccess) throws CryptoException {
        try {
            Class<?> implClass = Class.forName(
                    "com.licel.jcardsim.crypto.MessageDigestImpl");
            return (InitializedMessageDigest) implClass
                    .getConstructor(byte.class)
                    .newInstance(algorithm);
        } catch (Exception e) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
            return null;
        }
    }

    // ---- OneShot inner class ------------------------------------------------

    public static final class OneShot extends MessageDigest {

        private java.security.MessageDigest jdig;
        private byte algorithm;

        private OneShot(byte algorithm, java.security.MessageDigest dig) {
            this.algorithm = algorithm;
            this.jdig = dig;
        }

        /**
         * Fixed open(): jcardsim's original is "aconst_null; areturn" — always null.
         * This version creates a real java.security.MessageDigest backed instance.
         */
        public static OneShot open(byte algorithm) throws CryptoException {
            String name = algToJavaName(algorithm);
            if (name == null) {
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null;
            }
            try {
                java.security.MessageDigest dig =
                        java.security.MessageDigest.getInstance(name);
                return new OneShot(algorithm, dig);
            } catch (NoSuchAlgorithmException e) {
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null;
            }
        }

        public void close() {
            jdig = null;
        }

        @Override
        public byte getAlgorithm() {
            return algorithm;
        }

        @Override
        public byte getLength() {
            return (byte) jdig.getDigestLength();
        }

        @Override
        public short doFinal(byte[] inBuf, short inOff, short inLen,
                byte[] outBuf, short outOff) throws CryptoException {
            jdig.reset();
            jdig.update(inBuf, inOff, inLen);
            byte[] result = jdig.digest();
            System.arraycopy(result, 0, outBuf, outOff, result.length);
            return (short) result.length;
        }

        @Override
        public void update(byte[] inBuf, short inOff, short inLen)
                throws CryptoException {
            jdig.update(inBuf, inOff, inLen);
        }

        @Override
        public void reset() {
            jdig.reset();
        }
    }

    // ---- helpers ------------------------------------------------------------

    static String algToJavaName(byte algorithm) {
        switch (algorithm) {
            case ALG_SHA:       return "SHA-1";
            case ALG_MD5:       return "MD5";
            case ALG_RIPEMD160: return "RIPEMD160";
            case ALG_SHA_256:   return "SHA-256";
            case ALG_SHA_384:   return "SHA-384";
            case ALG_SHA_512:   return "SHA-512";
            case ALG_SHA_224:   return "SHA-224";
            case ALG_SHA3_224:  return "SHA3-224";
            case ALG_SHA3_256:  return "SHA3-256";
            case ALG_SHA3_384:  return "SHA3-384";
            case ALG_SHA3_512:  return "SHA3-512";
            default:            return null;
        }
    }
}
