// Host-only javax.smartcardio adapter for the pinned upstream JCAlgTest client.
// It uses the simulator's existing line-oriented APDU transport.
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactorySpi;

public final class MicroCardTerminal {
    private static final String NAME = "MicroCard host JCVM";
    private static final HexFormat HEX = HexFormat.of();

    private MicroCardTerminal() {}

    public static final class Factory extends TerminalFactorySpi {
        @Override
        protected CardTerminals engineTerminals() {
            return new Terminals();
        }
    }

    public static final class ProviderImpl extends Provider {
        public ProviderImpl() {
            super("MicroCard", "1.0", "MicroCard host JCVM APDU transport");
            put("TerminalFactory.MicroCard", Factory.class.getName());
        }
    }

    private static final class Terminals extends CardTerminals {
        private final Terminal terminal = new Terminal();

        @Override
        public List<CardTerminal> list(State state) {
            return state == State.CARD_ABSENT || state == State.CARD_REMOVAL
                ? List.of() : List.of(terminal);
        }

        @Override
        public boolean waitForChange(long timeout) {
            return false;
        }
    }

    private static final class Terminal extends CardTerminal {
        private Session active;

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public synchronized Card connect(String protocol) throws CardException {
            if (!"*".equals(protocol) && !"T=1".equals(protocol)) {
                throw new CardException("Unsupported protocol: " + protocol);
            }
            if (active == null || active.closed) {
                active = new Session();
            }
            return active;
        }

        @Override
        public boolean isCardPresent() {
            return true;
        }

        @Override
        public boolean waitForCardPresent(long timeout) {
            return true;
        }

        @Override
        public boolean waitForCardAbsent(long timeout) {
            return false;
        }

        @Override
        public String toString() {
            return NAME;
        }
    }

    private static final class Session extends Card {
        private final Process process;
        private final BufferedReader input;
        private final BufferedWriter output;
        private final Channel channel = new Channel(this);
        private boolean closed;

        Session() throws CardException {
            String simulator = System.getProperty("microcard.simulator");
            String keys = System.getProperty("microcard.keys");
            String state = System.getProperty("microcard.state");
            if (simulator == null || keys == null || state == null) {
                throw new CardException("Missing MicroCard simulator, keys, or state path");
            }
            try {
                process = new ProcessBuilder(simulator, "serve-jcvm-managed", keys, state)
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
                input = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.US_ASCII));
                output = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.US_ASCII));
            } catch (IOException error) {
                throw new CardException("Cannot start MicroCard simulator", error);
            }
        }

        synchronized byte[] exchange(byte[] command) throws CardException {
            if (closed || !process.isAlive()) {
                throw new CardException("MicroCard simulator is not running");
            }
            try {
                output.write(HEX.formatHex(command));
                output.newLine();
                output.flush();
                String line = input.readLine();
                if (line == null) {
                    throw new CardException("MicroCard simulator stopped during an APDU");
                }
                byte[] response = HEX.parseHex(line);
                if (response.length < 2) {
                    throw new CardException("MicroCard simulator returned a short APDU");
                }
                return response;
            } catch (IOException | IllegalArgumentException error) {
                throw new CardException("MicroCard APDU transport failed", error);
            }
        }

        @Override
        public ATR getATR() {
            return new ATR(new byte[] {0x3b, (byte) 0x80, 0x01, (byte) 0x81});
        }

        @Override
        public String getProtocol() {
            return "T=1";
        }

        @Override
        public CardChannel getBasicChannel() {
            return channel;
        }

        @Override
        public CardChannel openLogicalChannel() throws CardException {
            throw new CardException("Host JCVM supports the basic channel only");
        }

        @Override
        public void beginExclusive() {}

        @Override
        public void endExclusive() {}

        @Override
        public byte[] transmitControlCommand(int code, byte[] command) throws CardException {
            throw new CardException("Control commands are unavailable on the host transport");
        }

        @Override
        public synchronized void disconnect(boolean reset) throws CardException {
            if (closed) return;
            closed = true;
            try {
                output.close();
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    throw new CardException("MicroCard simulator did not stop");
                }
                if (process.exitValue() != 0) {
                    throw new CardException("MicroCard simulator exited with " + process.exitValue());
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new CardException("Cannot close MicroCard simulator", error);
            } catch (IOException error) {
                throw new CardException("Cannot close MicroCard simulator", error);
            }
        }
    }

    private static final class Channel extends CardChannel {
        private final Session card;

        Channel(Session card) {
            this.card = card;
        }

        @Override
        public Card getCard() {
            return card;
        }

        @Override
        public int getChannelNumber() {
            return 0;
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) throws CardException {
            return new ResponseAPDU(card.exchange(command.getBytes()));
        }

        @Override
        public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
            byte[] bytes = new byte[command.remaining()];
            command.get(bytes);
            byte[] answer = card.exchange(bytes);
            if (answer.length > response.remaining()) {
                throw new CardException("Response buffer is too small");
            }
            response.put(answer);
            return answer.length;
        }

        @Override
        public void close() {}
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.smartcardio.TerminalFactory.DefaultType", "MicroCard");
        Security.insertProviderAt(new ProviderImpl(), 1);
        if (!"MicroCard".equals(javax.smartcardio.TerminalFactory.getDefaultType())) {
            throw new IllegalStateException("MicroCard terminal provider was not selected");
        }
        Class.forName("algtestjclient.AlgTestJClient")
            .getMethod("main", String[].class).invoke(null, (Object) args);
    }
}
