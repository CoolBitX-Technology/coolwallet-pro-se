/*
 * Shadow class for NXP JCOP KeyAgreementX (All-in-One Version)
 */
package com.nxp.id.jcopx.security;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;

// Bouncy Castle Imports
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.math.BigInteger;

/**
 * NXP JCOP KeyAgreementX Shadow Implementation
 */
public class KeyAgreementX extends KeyAgreement {

    private byte algorithm;
    private ECPrivateKey privateKey;
    private ECDomainParameters bcParams;
    private BigInteger d;

    // 建構子
    protected KeyAgreementX(byte algorithm) {
        this.algorithm = algorithm;
    }

    // --- 3. Factory Method ---
    public static KeyAgreementX getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {

        if (algorithm == ALG_EC_SVDP_DH_PLAIN_XY || algorithm == ALG_EC_SVDP_DH_PLAIN) {
            return new KeyAgreementX(algorithm);
        }

        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        return null;
    }

    // --- 4. 實作標準抽象方法 (Override KeyAgreement) ---

    // ★★★ 補上這個方法 (解決目前的錯誤) ★★★
    @Override
    public byte getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public void init(PrivateKey key) throws CryptoException {
        try {
            if (key == null) {
                System.out.println("DEBUG: KeyAgreementX.init ERROR: Key is null!");
                CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
            }

            // 檢查型別並轉型
            if (!(key instanceof ECPrivateKey)) {
                System.out.println("DEBUG: KeyAgreementX.init ERROR: Key is not ECPrivateKey");
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }

            this.privateKey = (ECPrivateKey) key;

            // 3. 檢查 Key 是否已初始化 (是否有 S 值)
            // 在 JCardSim 中，如果 Key 沒設過 S，呼叫 getS 可能會拋出異常或回傳 0
            if (!this.privateKey.isInitialized()) {
                System.out.println(
                        "DEBUG: KeyAgreementX.init ERROR: Private Key is NOT initialized (isInitialized() returned false)");
                // 繼續往下試試看，有時候 isInitialized 實作不準
            }

            // 4. 從 ECPrivateKey 讀取實際的曲線參數，而非寫死曲線名稱
            byte[] fieldBuf = new byte[32];
            byte[] aBuf = new byte[32];
            byte[] bBuf = new byte[32];
            byte[] gBuf = new byte[65];
            byte[] nBuf = new byte[32];

            short fieldLen = this.privateKey.getField(fieldBuf, (short) 0);
            short aLen = this.privateKey.getA(aBuf, (short) 0);
            short bLen = this.privateKey.getB(bBuf, (short) 0);
            short gLen = this.privateKey.getG(gBuf, (short) 0);
            short nLen = this.privateKey.getR(nBuf, (short) 0);

            byte[] fieldBytes = java.util.Arrays.copyOf(fieldBuf, fieldLen);
            byte[] aBytes = java.util.Arrays.copyOf(aBuf, aLen);
            byte[] bBytes = java.util.Arrays.copyOf(bBuf, bLen);
            byte[] gBytes = java.util.Arrays.copyOf(gBuf, gLen);
            byte[] nBytes = java.util.Arrays.copyOf(nBuf, nLen);

            BigInteger p = new BigInteger(1, fieldBytes);
            BigInteger aCurve = new BigInteger(1, aBytes);
            BigInteger bCurve = new BigInteger(1, bBytes);
            BigInteger order = new BigInteger(1, nBytes);

            ECCurve curve = new ECCurve.Fp(p, aCurve, bCurve, order, BigInteger.ONE);
            ECPoint generator = curve.decodePoint(gBytes);
            this.bcParams = new ECDomainParameters(curve, generator, order, BigInteger.ONE);

            // 5. 提取私鑰數值 (S)
            // 使用較大的 buffer 避免溢位
            byte[] buffer = new byte[65];
            int len = 0;
            try {
                len = privateKey.getS(buffer, (short) 0);
            } catch (Exception e) {
                System.out.println(
                        "DEBUG: KeyAgreementX.init ERROR: Failed to get S from private key.");
                e.printStackTrace(); // 印出為什麼 getS 失敗
                CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
            }

            if (len == 0) {
                System.out.println("DEBUG: KeyAgreementX.init ERROR: Private Key S length is 0!");
                CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
            }

            // 複製出真實的私鑰 bytes
            byte[] sBytes = new byte[len];
            System.arraycopy(buffer, 0, sBytes, 0, len);

            // 轉換為 BigInteger (1 代表正數)
            this.d = new BigInteger(1, sBytes);
        } catch (CryptoException ce) {
            throw ce; // 重新拋出已知的 JavaCard 錯誤
        } catch (Throwable t) {
            // ★★★ 捕捉所有未預期的錯誤 (包含 VerifyError, LinkageError, RuntimeException) ★★★
            System.out.println("DEBUG: KeyAgreementX.init CRITICAL ERROR!");
            System.out.println("DEBUG: Exception type: " + t.getClass().getName());
            System.out.println("DEBUG: Message: " + t.getMessage());
            t.printStackTrace(System.out);
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
    }
    // @Override
    // public void init(Key key) throws CryptoException {
    // if (!(key instanceof ECPrivateKey)) {
    // CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    // }
    // this.privateKey = (ECPrivateKey) key;

    // // 設定橢圓曲線參數 (預設嘗試 secp256k1)
    // ECNamedCurveParameterSpec spec =
    // ECNamedCurveTable.getParameterSpec("secp256k1");
    // if (spec == null) {
    // spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    // }
    // this.bcParams = new ECDomainParameters(spec.getCurve(), spec.getG(),
    // spec.getN(), spec.getH());

    // // 提取私鑰數值
    // try {
    // byte[] buffer = new byte[128];
    // int len = privateKey.getS(buffer, (short) 0);

    // byte[] sBytes = new byte[len];
    // System.arraycopy(buffer, 0, sBytes, 0, len);

    // this.d = new BigInteger(1, sBytes);
    // System.out.println("DEBUG: KeyAgreementX init success.");

    // } catch (Exception e) {
    // e.printStackTrace();
    // CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
    // }
    // }

    @Override
    public short generateSecret(byte[] publicData, short publicOffset, short publicLength,
            byte[] secret, short secretOffset) throws CryptoException {
        try {
            // 解析公鑰
            byte[] pubBytes = new byte[publicLength];
            System.arraycopy(publicData, publicOffset, pubBytes, 0, publicLength);

            ECPoint Q = bcParams.getCurve().decodePoint(pubBytes);

            // ECDH 運算
            ECPoint P = Q.multiply(d).normalize();

            if (P.isInfinity()) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }

            byte[] xBytes = P.getAffineXCoord().getEncoded();
            byte[] yBytes = P.getAffineYCoord().getEncoded();

            int outputLen = 0;

            if (algorithm == ALG_EC_SVDP_DH_PLAIN_XY) {
                // 輸出 0x04 || X || Y
                if (secret.length - secretOffset < 1 + xBytes.length + yBytes.length) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                secret[secretOffset] = 0x04; // Uncompressed point format indicator
                System.arraycopy(xBytes, 0, secret, secretOffset + 1, xBytes.length);
                System.arraycopy(yBytes, 0, secret, secretOffset + 1 + xBytes.length,
                        yBytes.length);
                outputLen = 1 + xBytes.length + yBytes.length;
            } else {
                // 輸出 X
                if (secret.length - secretOffset < xBytes.length) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                System.arraycopy(xBytes, 0, secret, secretOffset, xBytes.length);
                outputLen = xBytes.length;
            }

            return (short) outputLen;

        } catch (Exception e) {
            e.printStackTrace();
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return 0;
    }
}
