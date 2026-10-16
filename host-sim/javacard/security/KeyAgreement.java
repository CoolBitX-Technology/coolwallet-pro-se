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
    // Must match the JavaCard API value (6): applet code is compiled against
    // api_classic.jar, which inlines this constant. NXP's own value (126)
    // lives on KeyAgreementX.
    public static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6;
    public static final byte ALG_DH_PLAIN = 7;

    protected KeyAgreement() {
    }

    public static KeyAgreement getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        // 攔截標準與 NXP 演算法 ID -> 轉發給 KeyAgreementX
        // jcardsim's KeyAgreementImpl computes a wrong secret when the private
        // key S has a leading zero byte (getS returns 31 bytes).
        if (algorithm == ALG_EC_SVDP_DH_PLAIN_XY ||
                algorithm == KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY ||
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