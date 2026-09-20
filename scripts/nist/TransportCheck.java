package dev.mistial.tools.openfips201.nist;

import java.util.HexFormat;
import javax.smartcardio.CardException;

/** One lifecycle check for the bridge, independent of the separately installed NIST runner. */
final class TransportCheck {
    private static void exchange(MicroCardNistTransport card, String command, int expected) throws Exception {
        byte[] response = card.transmit(HexFormat.of().parseHex(command));
        int sw = (response[response.length - 2] & 255) << 8 | response[response.length - 1] & 255;
        if (sw != expected) throw new AssertionError(String.format("Expected %04X, received %04X", expected, sw));
    }

    public static void main(String[] args) throws Exception {
        String select = "00A404000BA00000030800001000010000";
        try (MicroCardNistTransport card = new MicroCardNistTransport()) {
            exchange(card, select, 0x9000);
            exchange(card, "00200080", 0x63c6);
            exchange(card, "0020008008313233343536FFFF", 0x63c5);
            card.reset();
            exchange(card, select, 0x9000);
            exchange(card, "00200080", 0x63c5);
            exchange(card, "0020008008313233343536FFFF", 0x63c4);
            try {
                MicroCardNistTransport.unsupportedContactless().reset();
                throw new AssertionError("Contactless unexpectedly supported");
            } catch (CardException expected) { }
            card.close();
            try {
                card.transmit(HexFormat.of().parseHex(select));
                throw new AssertionError("Closed transport accepted a command");
            } catch (CardException expected) { }
        }
        try (MicroCardNistTransport independent = new MicroCardNistTransport()) {
            exchange(independent, select, 0x9000);
            exchange(independent, "00200080", 0x63c6);
        }
        System.out.println("PASS: upstream transport binding, persistent reset, isolated vectors and explicit contactless rejection");
    }
}
