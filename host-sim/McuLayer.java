import com.licel.jcardsim.base.Simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Simulates the MCU layer from coolwallet-jcvm (MicroCentralService).
 *
 * Responsibilities:
 *   Pre-processing:
 *     INS 0xA6 (getTransaction) — extend data to 256 zero bytes (Case 3 Extended APDU body)
 *
 *   Post-processing (on 9000 response):
 *     INS 0x10 P1=1 (register)  — save request body to env for startup replay
 *     INS 0x56 (reset)           — clear env file
 *     INS 0x46 (prepareTx)       — auto-authorize by immediately sending INS 0x38
 *
 *   Startup (setupStorage):
 *     If env has a saved register, replay INS 0x10 P1=1 to restore pairing state.
 *
 * Env file: coolwallet-pro-se.env  (Java Properties format)
 *   register = <hex of encrypted APDU body sent for INS 0x10 P1=1>
 */
public class McuLayer {

    public static final String ENV_FILE = "coolwallet-pro-se.env";

    private static final int INS_REGISTER   = 0x10;
    private static final int INS_RESET      = 0x56;
    private static final int INS_GET_TX     = 0xA6;
    private static final int INS_PREPARE_TX = 0x46;
    private static final int INS_AUTHORIZE  = 0x38;

    // ---- Pre-processing -----------------------------------------------------

    /**
     * Applies MCU pre-processing to the data field before sending to the applet.
     * INS 0xA6: replace data with 256 zero bytes (512 hex chars) so the applet
     * has a full buffer to write the serialized transaction into.
     */
    public static String preProcess(int cla, int ins, String data) {
        if (cla == 0x80 && ins == INS_GET_TX) {
            return repeat('0', 512);
        }
        return data;
    }

    // ---- Post-processing ----------------------------------------------------

    /**
     * Applies MCU post-processing after a successful (9000) response.
     *
     * @param ins         instruction byte of the command that was sent
     * @param p1          P1 byte (used to distinguish register vs restore)
     * @param requestData hex data field of the original APDU request
     * @param responseHex full hex response from the applet including SW
     * @param sim         jcardsim Simulator instance (for auto-authorize)
     */
    public static void postProcess(int ins, int p1, String requestData,
            String responseHex, Simulator sim) {
        if (!responseHex.toUpperCase().endsWith("9000")) return;

        switch (ins) {
            case INS_REGISTER:
                if (p1 == 1) {
                    handleRegister(requestData);
                }
                break;
            case INS_RESET:
                resetEnv();
                System.out.println("[MCU] Card state reset — env cleared");
                break;
            case INS_PREPARE_TX:
                autoAuthorize(sim);
                break;
        }
    }

    private static void handleRegister(String requestData) {
        Properties env = loadEnv();
        env.setProperty("register", requestData);
        saveEnv(env);
        System.out.println("[MCU] Register saved to " + ENV_FILE);
    }

    private static void autoAuthorize(Simulator sim) {
        // After prepareTx (INS 0x46) succeeds, the MCU confirms on behalf of the user.
        byte[] authApdu = {(byte) 0x80, (byte) INS_AUTHORIZE, 0, 0};
        byte[] result = sim.transmitCommand(authApdu);
        String resp = bytesToHex(result);
        System.out.println("[MCU] Auto-authorize (INS 0x38): " + resp);
    }

    // ---- Startup restoration ------------------------------------------------

    /**
     * Called once after the simulator is initialized. If a previous session saved
     * a register (INS 0x10 P1=1 body), replays it so the pairing state is restored.
     * The SE_TRANS key is derived deterministically, so the same ECDH-encrypted
     * APDU body decrypts correctly on every restart.
     */
    public static void setupStorage(Simulator sim) {
        if (!new File(ENV_FILE).exists()) {
            saveEnv(new Properties());
            System.out.println("[MCU] Created " + ENV_FILE + " (empty — will be populated after register)");
        }

        Properties env = loadEnv();
        String register = env.getProperty("register");
        if (register == null || register.isEmpty()) {
            System.out.println("[MCU] No saved state — starting fresh");
            return;
        }

        System.out.println("[MCU] Restoring register from " + ENV_FILE + " ...");
        byte[] apdu = buildApdu(0x80, INS_REGISTER, 1, 0, register);
        byte[] result = sim.transmitCommand(apdu);
        String resp = bytesToHex(result);
        if (resp.toUpperCase().endsWith("9000")) {
            System.out.println("[MCU] Register restored successfully");
        } else {
            System.out.println("[MCU] Register restore failed: " + resp
                    + " (env may be stale — delete " + ENV_FILE + " to reset)");
        }
    }

    // ---- JSON parsing -------------------------------------------------------

    /**
     * Parses {cla, ins, p1, p2} from a simple JSON body.
     * Supports integer values only (no hex strings).
     * Returns int[]{cla, ins, p1, p2}.
     */
    public static int[] parseJsonFields(String json) throws Exception {
        return new int[]{
                parseIntField(json, "cla"),
                parseIntField(json, "ins"),
                parseIntField(json, "p1"),
                parseIntField(json, "p2")
        };
    }

    /** Extracts the "data" string field from a simple JSON body. */
    public static String parseJsonData(String json) {
        Matcher m = Pattern.compile("\"data\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static int parseIntField(String json, String field) throws Exception {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!m.find()) throw new Exception("Missing JSON field: " + field);
        return Integer.parseInt(m.group(1));
    }

    // ---- APDU builder -------------------------------------------------------

    /**
     * Builds a raw APDU byte array from individual components.
     * Automatically selects Case 1 (no data), Case 3 (short), or Case 3 Extended.
     */
    public static byte[] buildApdu(int cla, int ins, int p1, int p2, String dataHex) {
        byte[] data = dataHex == null || dataHex.isEmpty()
                ? new byte[0] : hexToBytes(dataHex);

        if (data.length == 0) {
            return new byte[]{(byte) cla, (byte) ins, (byte) p1, (byte) p2};
        }
        if (data.length <= 255) {
            byte[] apdu = new byte[5 + data.length];
            apdu[0] = (byte) cla; apdu[1] = (byte) ins;
            apdu[2] = (byte) p1;  apdu[3] = (byte) p2;
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
            return apdu;
        }
        // Extended APDU: [CLA INS P1 P2 00 LCH LCL Data]
        byte[] apdu = new byte[7 + data.length];
        apdu[0] = (byte) cla; apdu[1] = (byte) ins;
        apdu[2] = (byte) p1;  apdu[3] = (byte) p2;
        apdu[4] = 0x00;
        apdu[5] = (byte) (data.length >> 8);
        apdu[6] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, apdu, 7, data.length);
        return apdu;
    }

    // ---- Env file helpers ---------------------------------------------------

    public static Properties loadEnv() {
        Properties props = new Properties();
        File f = new File(ENV_FILE);
        if (!f.exists()) return props;
        try (FileInputStream fis = new FileInputStream(f)) {
            props.load(fis);
        } catch (IOException e) {
            System.err.println("[MCU] Failed to load " + ENV_FILE + ": " + e.getMessage());
        }
        return props;
    }

    private static void saveEnv(Properties props) {
        try (FileOutputStream fos = new FileOutputStream(ENV_FILE)) {
            props.store(fos, "CoolWallet PRO-SE Simulator State");
        } catch (IOException e) {
            System.err.println("[MCU] Failed to save " + ENV_FILE + ": " + e.getMessage());
        }
    }

    private static void resetEnv() {
        File f = new File(ENV_FILE);
        if (f.exists()) f.delete();
    }

    // ---- Hex / byte utilities -----------------------------------------------

    public static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                    | Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }
}
