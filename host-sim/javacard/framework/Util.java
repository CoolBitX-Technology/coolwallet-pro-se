package javacard.framework;

/**
 * Shadow of jcardsim's javacard.framework.Util — placed first on the classpath
 * so it takes precedence over the jcardsim JAR.
 *
 * Fixes: arrayFillNonAtomic throws ArrayIndexOutOfBoundsException when bOff ==
 * bArray.length and bLen == 0, because jcardsim's bytecode does arr[bOff]
 * (baload) unconditionally before checking bLen. Real JavaCard hardware treats
 * length=0 as a no-op without validating the offset.
 *
 * All other methods are faithful re-implementations of jcardsim's behaviour.
 */
public class Util {

    public static final short arrayCopy(byte[] src, short srcOff,
            byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static final short arrayCopyNonAtomic(byte[] src, short srcOff,
            byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static final short arrayFillNonAtomic(byte[] bArray, short bOff,
            short bLen, byte bValue) {
        if (bLen < 0) throw new ArrayIndexOutOfBoundsException();
        // Guard: real JavaCard skips the fill entirely when bLen == 0,
        // even if bOff == bArray.length. jcardsim's bytecode accesses
        // arr[bOff] before checking bLen, causing AIOOBE in that edge case.
        if (bLen == 0) return bOff;
        for (short i = 0; i < bLen; i++) {
            bArray[(short) (bOff + i)] = bValue;
        }
        return (short) (bOff + bLen);
    }

    public static final short arrayFill(byte[] bArray, short bOff,
            short bLen, byte bValue) {
        return arrayFillNonAtomic(bArray, bOff, bLen, bValue);
    }

    public static final byte arrayCompare(byte[] src, short srcOff,
            byte[] dest, short destOff, short length) {
        if (length < 0) throw new ArrayIndexOutOfBoundsException();
        for (short i = 0; i < length; i++) {
            int s = src[(short) (srcOff + i)] & 0xFF;
            int d = dest[(short) (destOff + i)] & 0xFF;
            if (s < d) return (byte) -1;
            if (s > d) return (byte) 1;
        }
        return (byte) 0;
    }

    public static final short makeShort(byte b1, byte b2) {
        return (short) (((b1 & 0xFF) << 8) | (b2 & 0xFF));
    }

    public static final short getShort(byte[] bArray, short bOff) {
        return (short) (((bArray[bOff] & 0xFF) << 8) | (bArray[(short) (bOff + 1)] & 0xFF));
    }

    public static final short setShort(byte[] bArray, short bOff, short sValue) {
        bArray[bOff] = (byte) (sValue >> 8);
        bArray[(short) (bOff + 1)] = (byte) (sValue & 0xFF);
        return (short) (bOff + 2);
    }
}
