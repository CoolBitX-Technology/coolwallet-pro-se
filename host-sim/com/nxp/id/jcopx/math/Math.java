package com.nxp.id.jcopx.math;

import java.math.BigInteger;

public final class Math {

    public Math() {}

    private static BigInteger toBigInteger(byte[] data, short offset, short len) {
        byte[] buf = new byte[len + 1];
        buf[0] = 0x00; // ensure positive
        System.arraycopy(data, offset, buf, 1, len);
        return new BigInteger(buf);
    }

    private static void toByteArray(BigInteger bi, byte[] data, short offset, short len) {
        byte[] biBytes = bi.toByteArray();
        // The array might be longer due to sign bit (extra leading 0x00), or shorter
        int start = 0;
        if (biBytes[0] == 0x00 && biBytes.length > 1) {
            start = 1;
        }
        int copyLen = biBytes.length - start;
        if (copyLen > len) {
            // Should not happen if modulo is correct, but just in case, copy the lower bytes
            start += (copyLen - len);
            copyLen = len;
        }
        // Pad with zeros to fill the entire 'len' buffer (right aligned)
        for (int i = 0; i < len - copyLen; i++) {
            data[offset + i] = 0x00;
        }
        System.arraycopy(biBytes, start, data, offset + len - copyLen, copyLen);
    }

    public static void modularReduce(byte[] data, short dataOff, short dataLen, byte[] mod, short modOff, short modLen) {
        BigInteger d = toBigInteger(data, dataOff, dataLen);
        BigInteger m = toBigInteger(mod, modOff, modLen);
        BigInteger r = d.mod(m);
        toByteArray(r, data, dataOff, dataLen);
    }

    public static void modularMultiply(byte[] data, short dataOff, short dataLen, byte[] data2, short data2Off, short data2Len, byte[] mod, short modOff, short modLen) {
        BigInteger d1 = toBigInteger(data, dataOff, dataLen);
        BigInteger d2 = toBigInteger(data2, data2Off, data2Len);
        BigInteger m = toBigInteger(mod, modOff, modLen);
        BigInteger r = d1.multiply(d2).mod(m);
        toByteArray(r, data, dataOff, dataLen);
    }

    public static void modularAdd(byte[] data, short dataOff, short dataLen, byte[] data2, short data2Off, short data2Len, byte[] mod, short modOff, short modLen) {
        BigInteger d1 = toBigInteger(data, dataOff, dataLen);
        BigInteger d2 = toBigInteger(data2, data2Off, data2Len);
        BigInteger m = toBigInteger(mod, modOff, modLen);
        BigInteger r = d1.add(d2).mod(m);
        toByteArray(r, data, dataOff, dataLen);
    }

    public static void modularSubtract(byte[] data, short dataOff, short dataLen, byte[] data2, short data2Off, short data2Len, byte[] mod, short modOff, short modLen) {
        BigInteger d1 = toBigInteger(data, dataOff, dataLen);
        BigInteger d2 = toBigInteger(data2, data2Off, data2Len);
        BigInteger m = toBigInteger(mod, modOff, modLen);
        
        // Ensure positive result for modulo since d1 - d2 could be negative
        BigInteger diff = d1.subtract(d2);
        // Using mod(m) directly handles negative correctly in Java's BigInteger (returns positive remainder)
        BigInteger r = diff.mod(m);
        
        toByteArray(r, data, dataOff, dataLen);
    }
}
