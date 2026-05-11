/*
 * Shadow class for javacard.security.KeyAgreement
 * Purpose: Remove 'final' from getInstance to allow KeyAgreementX to extend it.
 */
package javacard.security;

import com.licel.jcardsim.crypto.KeyAgreementImpl;
import com.nxp.id.jcopx.security.KeyAgreementX;

public abstract class KeyAgreement {

    // --- 標準常數定義 ---
    public static final byte ALG_EC_SVDP_DH = 1;
    public static final byte ALG_EC_SVDP_DHC = 2;
    public static final byte ALG_EC_SVDP_DH_PLAIN = 3;
    public static final byte ALG_EC_SVDP_DHC_PLAIN = 4;
    public static final byte ALG_EC_PACE_GM = 5;
    public static final byte ALG_EC_SVDP_DH_PLAIN_XY = 126;
    public static final byte ALG_DH_PLAIN = 7;

    protected KeyAgreement() {
    }

    public static KeyAgreement getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        // 攔截 NXP 演算法 ID -> 轉發給 KeyAgreementX
        if (algorithm == KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY ||
                algorithm == KeyAgreementX.ALG_EC_SVDP_DH_PLAIN) {
            return KeyAgreementX.getInstance(algorithm, externalAccess);
        }
        return new KeyAgreementImpl(algorithm);
    }

    // =================================================================
    // ★★★ 修正回歸：參數改回 Key (符合標準 API) ★★★
    // =================================================================
    public abstract void init(PrivateKey privateKey) throws CryptoException;

    public abstract byte getAlgorithm();

    public abstract short generateSecret(byte[] publicData, short publicOffset, short publicLength,
            byte[] secret, short secretOffset) throws CryptoException;

}