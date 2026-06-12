import com.licel.jcardsim.base.Simulator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import javacard.framework.AID;
import javacard.framework.SystemException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * HTTP server + jCardSim simulator listening on port 9527.
 *
 * Endpoints:
 *   GET  /ping                    -> "pong"
 *   POST /apdu                    -> raw hex APDU in, raw hex response out (for coolwallet3-se-test)
 *   POST /card/sendAPDUCommand    -> JSON {cla,ins,p1,p2,data} in, lowercase hex response out
 *                                    (coolwallet-jcvm compatible, includes MCU pre/post processing)
 */
public class SimHttpServer {

    private static Simulator simulator;

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider()); // 強制加入 BC
        initSimulator();
        McuLayer.setupStorage(simulator);

        int port = 9527;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // Simple health check
        server.createContext("/ping", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String response = "pong";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        });

        // APDU endpoint backed by jCardSim
        server.createContext("/apdu", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String method = exchange.getRequestMethod();
                if (!"POST".equalsIgnoreCase(method)) {
                    String msg = "Use POST with raw hex APDU body";
                    byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(405, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                    return;
                }

                String bodyHex;
                try (InputStream is = exchange.getRequestBody()) {
                    // Java 8 compatible readAllBytes()
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[256];
                    int n;
                    while ((n = is.read(buf)) != -1) {
                        baos.write(buf, 0, n);
                    }
                    byte[] body = baos.toByteArray();
                    bodyHex = new String(body, StandardCharsets.UTF_8).trim();
                }

                if (bodyHex == null || bodyHex.isEmpty()) {
                    String msg = "Empty APDU";
                    byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                    return;
                }

                byte[] apduBytes;
                try {
                    apduBytes = hexToBytes(bodyHex);
                } catch (IllegalArgumentException e) {
                    String msg = "Invalid hex: " + e.getMessage();
                    byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(bytes);
                    }
                    return;
                }

                // jcardsim 3.x: transmitCommand 接收 / 回傳的都是 byte[]
                byte[] respApduBytes = simulator.transmitCommand(apduBytes);
                String respHex = bytesToHex(respApduBytes);
                byte[] respBody = respHex.getBytes(StandardCharsets.UTF_8);

                exchange.sendResponseHeaders(200, respBody.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(respBody);
                }
            }
        });

        // coolwallet-jcvm compatible endpoint with MCU pre/post processing
        server.createContext("/card/sendAPDUCommand", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String method = exchange.getRequestMethod();
                if (!"POST".equalsIgnoreCase(method)) {
                    String msg = "Use POST with JSON body: {cla,ins,p1,p2,data}";
                    byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(405, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
                    return;
                }

                String jsonBody;
                try (InputStream is = exchange.getRequestBody()) {
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                    jsonBody = baos.toString(StandardCharsets.UTF_8.name()).trim();
                }

                String respHex;
                try {
                    int[] fields = McuLayer.parseJsonFields(jsonBody);
                    int cla = fields[0], ins = fields[1], p1 = fields[2], p2 = fields[3];
                    String data = McuLayer.parseJsonData(jsonBody);

                    data = McuLayer.preProcess(cla, ins, data);

                    byte[] apduBytes = McuLayer.buildApdu(cla, ins, p1, p2, data);
                    byte[] respBytes = simulator.transmitCommand(apduBytes);
                    respHex = McuLayer.bytesToHex(respBytes);

                    McuLayer.postProcess(ins, p1, data, respHex, simulator);
                } catch (Exception e) {
                    System.err.println("[/card/sendAPDUCommand] Error: " + e.getMessage());
                    e.printStackTrace();
                    String msg = "Error: " + e.getMessage();
                    byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, bytes.length);
                    try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
                    return;
                }

                byte[] respBody = respHex.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, respBody.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(respBody); }
            }
        });

        server.setExecutor(null); // default executor
        System.out.println("HTTP jCardSim server listening on http://localhost:" + port);
        server.start();
    }

    /**
     * Initialize jCardSim simulator.
     *
     * 目前預設：
     * 1. 嘗試安裝/選取 Backup StoreApplet（BackupApplet）
     * 2. 若有問題可以改成安裝 TestApplet 來測試管線
     */
    private static void initSimulator() {
        simulator = new Simulator();

        try {
            // installParams = [ length(AID) ] [ AID bytes ] [ 0x00 ]
            {
                byte[] backupAppletAidBytes = "BackupApplet".getBytes(StandardCharsets.US_ASCII);
                AID backupAppletAid = new AID(backupAppletAidBytes, (short) 0, (byte) backupAppletAidBytes.length);
                short aidLen = (short) backupAppletAidBytes.length;
                byte[] installParams = new byte[aidLen + 2];
                installParams[0] = (byte) aidLen;
                System.arraycopy(backupAppletAidBytes, 0, installParams, 1, aidLen);
                installParams[aidLen + 1] = (byte) 0x00;

                // 使用另一個支援傳入 install data 的 installApplet 方法
                simulator.installApplet(
                        backupAppletAid,
                        coolbitx.sio.StoreApplet.class,
                        installParams, // bArray
                        (short) 0, // bOffset
                        (byte) installParams.length // bLength
                );
                System.out.println("Installed BackupStoreApplet in jCardSim successfully.");
                simulator.selectApplet(backupAppletAid);

                byte[] cardIdBytes = "CWP999999".getBytes(StandardCharsets.US_ASCII);
                byte cardIdLen = (byte) cardIdBytes.length;
                byte[] cardIdCommand = new byte[5 + cardIdLen];
                cardIdCommand[0] = (byte) 0x80;
                cardIdCommand[1] = (byte) 0x00;
                cardIdCommand[2] = (byte) 0x00;
                cardIdCommand[3] = (byte) 0x00;
                cardIdCommand[4] = cardIdLen;
                System.arraycopy(cardIdBytes, 0, cardIdCommand, 5, cardIdLen);
                simulator.transmitCommand(cardIdCommand);
                System.out.println("BackupStoreApplet set card id in jCardSim successfully.");
            }

            {
                byte[] mainAppletAidBytes = "CoolWalletPRO".getBytes(StandardCharsets.US_ASCII);
                AID mainAppletAid = new AID(mainAppletAidBytes, (short) 0, (byte) mainAppletAidBytes.length);
                short aidLen = (short) mainAppletAidBytes.length;
                byte[] installParams = new byte[aidLen + 3];
                installParams[0] = (byte) aidLen;
                System.arraycopy(mainAppletAidBytes, 0, installParams, 1, aidLen);
                installParams[aidLen + 1] = (byte) 0x00;

                // 使用另一個支援傳入 install data 的 installApplet 方法
                simulator.installApplet(
                        mainAppletAid,
                        coolbitx.Main.class,
                        installParams, // bArray
                        (short) 0, // bOffset
                        (byte) installParams.length // bLength
                );
                System.out.println("Installed MainApplet in jCardSim successfully.");
                simulator.selectApplet(mainAppletAid);
                System.out.println("Selected MainApplet in jCardSim successfully.");
            }

            return;
        } catch (SystemException se) {
            short reason = se.getReason();
            String hex = Integer.toHexString(reason & 0xFFFF).toUpperCase();
            System.out.println("StoreApplet install failed, SystemException reason="
                    + reason + " (0x" + hex + ")");
            se.printStackTrace(System.out);
        } catch (Throwable t) {
            System.out.println("StoreApplet install failed with non-SystemException:");
            t.printStackTrace(System.out);
        }

        // 如果 StoreApplet 無法安裝，就退回用簡單的 TestApplet 確認通路
        System.out.println("Falling back to coolbitx.sim.TestApplet.");
        byte[] testAidBytes = new byte[] {
                (byte) 'T', (byte) 'e', (byte) 's', (byte) 't',
                (byte) 'A', (byte) 'p', (byte) 'p'
        };
        AID testAid = new AID(testAidBytes, (short) 0, (byte) testAidBytes.length);
        simulator.installApplet(testAid, coolbitx.sim.TestApplet.class);
        System.out.println("Installed coolbitx.sim.TestApplet.");
        simulator.selectApplet(testAid);
        System.out.println("Selected coolbitx.sim.TestApplet.");
    }

    // --- Small hex utilities (no external deps) ---

    private static byte[] hexToBytes(String s) {
        String hex = s.replaceAll("\\s+", "");
        int len = hex.length();
        if (len == 0) {
            return new byte[0];
        }
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Odd-length hex string");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex char at " + i);
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
