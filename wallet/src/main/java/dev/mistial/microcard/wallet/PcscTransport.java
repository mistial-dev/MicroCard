package dev.mistial.microcard.wallet;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.util.List;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/** Shared PC/SC byte transport for wallet and acceptance tools. */
public final class PcscTransport {
    private PcscTransport() { }

    public static BIBO open(String reader) throws CardException {
        var terminals = TerminalFactory.getDefault().terminals().list();
        var matches = terminals.stream().filter(t -> t.getName().contains(reader)).toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Expected one reader matching '" + reader
                + "', found " + matches.size() + ": " + names(terminals));
        }
        var card = matches.getFirst().connect("*");
        return new BIBO() {
            public byte[] transceive(byte[] command) {
                try { return card.getBasicChannel().transmit(new CommandAPDU(command)).getBytes(); }
                catch (CardException error) { throw new BIBOException("PC/SC exchange failed", error); }
            }

            public void close() {
                try { card.disconnect(false); }
                catch (CardException ignored) { }
            }
        };
    }

    private static String names(List<javax.smartcardio.CardTerminal> terminals) {
        return terminals.stream().map(javax.smartcardio.CardTerminal::getName)
            .reduce((left, right) -> left + ", " + right).orElse("(none)");
    }
}
