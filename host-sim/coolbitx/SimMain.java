package coolbitx;

import javacard.framework.APDU;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import coolbitx.sio.StoreInterface;

/**
 * Simulator-only wrapper that logs exceptions before jcardsim swallows them.
 * Used instead of coolbitx.Main in SimHttpServer so that any exception
 * thrown from process() is printed to stderr before 6F00 is returned.
 */
public class SimMain extends Main {

    protected SimMain(byte[] bArray, short bOffset, short length) {
        super(bArray, bOffset, length);
    }

    /**
     * Mirrors Main.install() exactly but creates SimMain instead of Main,
     * so that our overridden process() is used for exception logging.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        byte aidLength = bArray[bOffset++];
        short aidOffset = bOffset;
        bOffset += aidLength;

        byte controlLength = bArray[bOffset++];
        bOffset += controlLength;

        byte paraLength = bArray[bOffset++];
        short paraOffset = bOffset;
        new SimMain(bArray, paraOffset, paraLength).register(bArray, aidOffset, aidLength);

        // Replicate the storeInterface initialization from Main.install
        storeAppAid = new AID(storeAid, (short) 0, (byte) storeAid.length);
        storeInterface = (StoreInterface) JCSystem.getAppletShareableInterfaceObject(storeAppAid, (byte) 0);
    }

    @Override
    public void process(APDU apdu) {
        try {
            super.process(apdu);
        } catch (Throwable t) {
            System.err.println("[SimMain] Exception in process(): " + t);
            t.printStackTrace(System.err);
            throw t;
        }
    }
}
