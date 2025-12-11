package coolbitx.sim;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * Minimal test applet for jCardSim:
 * - install: simple GP-compliant registration
 * - process: SELECT does nothing, all other commands just return 9000
 *
 * 用來確認 jCardSim + HTTP 管線是否正常，不依賴專案內其他邏輯。
 * 同時實作 ExtendedLength，讓 jCardSim 不會對 extended-length APDU 回 6700。
 */
public class TestApplet extends Applet implements ExtendedLength {

    private Cipher cipher;

    protected TestApplet() {
        // no state
        cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // 簡單的 GP-compliant install：忽略參數，直接註冊
        new TestApplet().register();
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();

        // 標準 SELECT APDU 直接略過（由 jCardSim 處理 SELECT 邏輯）
        if ((buf[ISO7816.OFFSET_CLA] == 0)
                && (buf[ISO7816.OFFSET_INS] == (byte) 0xA4)) {
            return;
        }

        // 其它任何 APDU 都直接回 9000，沒有 data
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    public final void uninstall() {
        cipher = null;
        JCSystem.requestObjectDeletion();
    }
}
