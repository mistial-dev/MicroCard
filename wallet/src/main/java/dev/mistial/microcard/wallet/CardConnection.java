package dev.mistial.microcard.wallet;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.keys.PlaintextKeys;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import javax.smartcardio.TerminalFactory;

/** GPPro owns every SCP03 cryptographic operation; adapters move APDU bytes only. */
final class CardConnection implements AutoCloseable {
    private final BIBO transport;
    private final GPSession session;
    private final boolean trace;

    CardConnection(BIBO transport, byte[] keys, boolean trace) throws Exception {
        this.transport = transport;
        this.trace = trace;
        try {
            if (keys.length != 32) throw new IllegalArgumentException("Management key file must contain 32 bytes");
            session = GPSession.connect(new APDUBIBO(transport), new AID("A000000151000000"));
            var cardKeys = PlaintextKeys.fromKeys(Arrays.copyOfRange(keys, 0, 16),
                Arrays.copyOfRange(keys, 16, 32), Arrays.copyOfRange(keys, 0, 16));
            session.openSecureChannel(cardKeys, GPSecureChannelVersion.valueOf(3, 0x20), null,
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC, GPSession.APDUMode.RMAC));
        } catch (Exception error) { transport.close(); throw error; }
    }

    ResponseAPDU exchange(int ins, byte[] data) throws Exception {
        if (data.length > 200) throw new IllegalArgumentException("Command exceeds the wallet short-APDU bound");
        ResponseAPDU response = session.transmit(new CommandAPDU(0x80, ins, 0, 0, data));
        if (trace) System.err.printf("SCP03/13 INS=%02X input=%d bytes [redacted] output=%d bytes SW=%04X%n",
            ins, data.length, response.getData().length, response.getSW());
        return response;
    }

    byte[] command(int ins, byte[] data) throws Exception {
        var response = exchange(ins, data);
        if (response.getSW() != 0x9000) throw new IOException(String.format("INS %02X rejected: SW=%04X", ins, response.getSW()));
        return response.getData();
    }

    public void close() { transport.close(); }

    static BIBO simulator(Path binary, Path keys, Path state) throws IOException {
        return new Simulator(binary, keys, state);
    }

    static BIBO reader(String name) throws Exception {
        var terminals = TerminalFactory.getDefault().terminals().list();
        var terminal = terminals.stream().filter(t -> t.getName().equals(name)).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Reader not found. Use readers to list exact names"));
        var card = terminal.connect("*");
        return new BIBO() {
            public byte[] transceive(byte[] command) {
                try { return card.getBasicChannel().transmit(new javax.smartcardio.CommandAPDU(command)).getBytes(); }
                catch (javax.smartcardio.CardException e) { throw new BIBOException("PC/SC exchange failed", e); }
            }
            public void close() { try { card.disconnect(false); } catch (javax.smartcardio.CardException ignored) { } }
        };
    }

    private static final class Simulator implements BIBO {
        private final Process process;
        private final InputStream input;
        private final OutputStream output;
        private final ExecutorService reads = Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
        Simulator(Path binary, Path keys, Path state) throws IOException {
            process = new ProcessBuilder(binary.toAbsolutePath().toString(), "serve-binary",
                keys.toAbsolutePath().toString(), state.toAbsolutePath().toString())
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            input = process.getInputStream(); output = process.getOutputStream();
        }
        public synchronized byte[] transceive(byte[] command) {
            if (command.length > 261) throw new BIBOException("Only short APDUs are supported");
            try {
                output.write(command.length & 255); output.write(command.length >>> 8);
                output.write(command); output.flush();
                return reads.submit(() -> {
                    int lo = input.read(), hi = input.read();
                    if (lo < 0 || hi < 0) throw new EOFException("Simulator stopped");
                    int size = lo | hi << 8;
                    if (size < 2 || size > 258) throw new IOException("Invalid response frame");
                    byte[] response = input.readNBytes(size);
                    if (response.length != size) throw new EOFException("Truncated response frame");
                    return response;
                }).get(30, TimeUnit.SECONDS);
            } catch (Exception error) {
                if (error instanceof InterruptedException) Thread.currentThread().interrupt();
                close(); throw new BIBOException("Simulator exchange failed", error);
            }
        }
        public void close() {
            reads.shutdownNow();
            try { output.close(); } catch (IOException ignored) { }
            try { if (!process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); process.destroyForcibly(); }
        }
    }
}
