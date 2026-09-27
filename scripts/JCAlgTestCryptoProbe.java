import javax.smartcardio.*;
import java.util.Arrays;

// Exercise JCAlgTest operations on the physical card, not just their factories.
public class JCAlgTestCryptoProbe {
    private static byte[] command(CardChannel channel, int cla, int ins, byte[] data) throws Exception {
        ResponseAPDU response = channel.transmit(new CommandAPDU(cla, ins, ins == 0xa4 ? 4 : 0, 0, data, 256));
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException(String.format("INS %02x returned %04x", ins, response.getSW()));
        }
        return response.getData();
    }

    public static void main(String[] args) throws Exception {
        String reader = args.length == 0 ? "MicroCard MicroCard virtual smart card" : args[0];
        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().stream()
            .filter(t -> t.getName().equals(reader))
            .findFirst().orElseThrow(() -> new IllegalStateException("Reader unavailable: " + reader));
        Card card = terminal.connect("*");
        try {
            CardChannel channel = card.getBasicChannel();
            byte[] aid = {0x4a, 0x43, 0x41, 0x6c, 0x67, 0x54, 0x65, 0x73, 0x74, 0x31};
            command(channel, 0x00, 0xa4, aid);
            for (int algorithm : new int[] {1, 2}) {
                byte[] prepare = {0, 0, 0, (byte) algorithm};
                byte[] result = command(channel, 0xb0, 0x35, prepare);
                if (!Arrays.equals(result, new byte[] {(byte) 0xaa})) {
                    throw new IllegalStateException("checksum prepare failed: " + Arrays.toString(result));
                }
                for (int method : new int[] {1, 5}) {
                    byte[] settings = new byte[22];
                    settings[3] = (byte) algorithm;
                    settings[11] = (byte) method;
                    settings[13] = 9;
                    settings[19] = 1;
                    settings[21] = 1;
                    result = command(channel, 0xb0, 0x46, settings);
                    if (!Arrays.equals(result, new byte[] {(byte) 0xaa})) {
                        throw new IllegalStateException("checksum operation failed: " + Arrays.toString(result));
                    }
                    System.out.printf("CRC%d method %d: success%n", algorithm == 1 ? 16 : 32, method);
                }
            }
            for (int algorithm : new int[] {1, 7}) { // SHA-1 and SHA-224
                byte[] prepare = {0, 0, 0, (byte) algorithm};
                byte[] result = command(channel, 0xb0, 0x34, prepare);
                if (!Arrays.equals(result, new byte[] {(byte) 0xaa})) {
                    throw new IllegalStateException("digest prepare failed: " + Arrays.toString(result));
                }
                for (int method : new int[] {2, 6, 4}) { // update, doFinal, reset
                    byte[] settings = new byte[22];
                    settings[3] = (byte) algorithm;
                    settings[11] = (byte) method;
                    settings[13] = 9;
                    settings[19] = 1;
                    settings[21] = 1;
                    result = command(channel, 0xb0, 0x41, settings);
                    if (!Arrays.equals(result, new byte[] {(byte) 0xaa})) {
                        throw new IllegalStateException("digest operation failed: " + Arrays.toString(result));
                    }
                    System.out.printf("SHA-%s method %d: success%n", algorithm == 1 ? "1" : "224", method);
                }
            }
            // Exercise the newly advertised AES CBC-MAC through the installed applet.
            byte[] macSettings = new byte[22];
            macSettings[3] = 18; // Signature.ALG_AES_MAC_128_NOPAD
            macSettings[7] = 15; // KeyBuilder.TYPE_AES
            macSettings[9] = (byte) 128;
            macSettings[13] = 16;
            macSettings[19] = 1;
            macSettings[21] = 1;
            byte[] prepared = command(channel, 0xb0, 0x32, macSettings);
            if (!Arrays.equals(prepared, new byte[] {(byte) 0xaa})) {
                throw new IllegalStateException("AES MAC prepare failed: " + Arrays.toString(prepared));
            }
            for (int method : new int[] {2, 10, 7}) { // update, sign, verify
                macSettings[11] = (byte) method;
                byte[] result = command(channel, 0xb0, 0x49, macSettings);
                if (!Arrays.equals(result, new byte[] {(byte) 0xaa})) {
                    throw new IllegalStateException("AES MAC operation failed: " + Arrays.toString(result));
                }
                System.out.printf("AES-128 MAC method %d: success%n", method);
            }
        } finally {
            card.disconnect(false);
        }
    }
}
