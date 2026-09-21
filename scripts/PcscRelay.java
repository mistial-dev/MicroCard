import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.HexFormat;
import javax.smartcardio.Card;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/** Keeps one PC/SC connection open while relaying line-delimited APDUs. */
public final class PcscRelay {
    private PcscRelay() { }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) throw new IllegalArgumentException("usage: PcscRelay READER");
        var terminal = TerminalFactory.getDefault().terminals().list().stream()
            .filter(item -> item.getName().equals(arguments[0]))
            .findFirst().orElseThrow(() -> new IllegalArgumentException("PC/SC reader not found: " + arguments[0]));
        Card card = terminal.connect("*");
        try (var input = new BufferedReader(new InputStreamReader(System.in));
             var output = new PrintWriter(System.out, true)) {
            for (String line; (line = input.readLine()) != null; ) {
                if (line.isBlank()) continue;
                byte[] response = card.getBasicChannel()
                    .transmit(new CommandAPDU(HexFormat.of().parseHex(line)))
                    .getBytes();
                output.println(HexFormat.of().formatHex(response));
            }
        } finally {
            card.disconnect(false);
        }
    }
}
