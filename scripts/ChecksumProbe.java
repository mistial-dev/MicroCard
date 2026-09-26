import javax.smartcardio.*;
import java.util.Arrays;

// Exercise JCAlgTest's checksum operations on the physical card, not just its factories.
public class ChecksumProbe {
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
        } finally {
            card.disconnect(false);
        }
    }
}
