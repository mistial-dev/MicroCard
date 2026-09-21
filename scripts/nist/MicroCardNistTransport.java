package dev.mistial.tools.openfips201.nist;

import dev.mistial.microcard.wallet.SimulatorTransport;
import dev.mistial.microcard.wallet.PcscTransport;
import java.io.IOException;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.nio.file.*;
import java.util.Comparator;
import java.util.HexFormat;
import javax.smartcardio.CardException;

/** Upstream NistCardTransport binding. Each vector starts from an isolated seed image. */
final class MicroCardNistTransport implements NistCardTransport {
    private final Path directory;
    private final SimulatorTransport transport;
    private final String physicalReader;
    private final byte[] physicalManagementKeys;
    private boolean closed;

    MicroCardNistTransport() throws IOException {
        String reader = System.getProperty("microcard.nist.reader");
        if (reader != null && !reader.isBlank()) {
            directory = null;
            transport = null;
            physicalReader = reader;
            String encodedKeys = System.getProperty("microcard.nist.management-key");
            if (encodedKeys == null) {
                throw new IOException("Physical NIST provisioning requires a management key");
            }
            try {
                physicalManagementKeys = HexFormat.of().parseHex(encodedKeys);
            } catch (IllegalArgumentException error) {
                throw new IOException("Invalid physical management key", error);
            }
            if (physicalManagementKeys.length != 32) {
                throw new IOException("Physical management key must contain 32 bytes");
            }
            return;
        }
        physicalReader = null;
        physicalManagementKeys = null;
        directory = Files.createTempDirectory("microcard-nist-");
        try {
            Path seed = Path.of(System.getProperty("microcard.nist.seed"));
            copyTree(seed, directory);
            transport = new SimulatorTransport(Path.of(System.getProperty("microcard.nist.sim")),
                directory.resolve("keys"), directory.resolve("state"), SimulatorTransport.Engine.JCVM);
        } catch (Exception error) {
            removeDirectory();
            throw new IOException("Cannot initialize MicroCard NIST transport", error);
        }
    }

    private static void copyTree(Path sourceRoot, Path destination) throws IOException {
        try (var paths = Files.walk(sourceRoot)) {
            for (Path source : paths.toList()) {
                if (Files.isSymbolicLink(source)) throw new IOException("Seed contains a symbolic link");
                Path target = destination.resolve(sourceRoot.relativize(source));
                if (Files.isDirectory(source)) Files.createDirectories(target);
                else Files.copy(source, target);
            }
        }
    }

    void saveSeed(Path destination) throws IOException {
        if (physicalReader != null) return;
        transport.close();
        Files.createDirectory(destination);
        copyTree(directory, destination);
    }

    BIBO openBibo() {
        if (physicalReader != null) {
            try {
                return PcscTransport.open(physicalReader);
            } catch (Exception error) {
                throw new BIBOException("Cannot connect to physical MicroCard", error);
            }
        }
        return new BIBO() {
            public byte[] transceive(byte[] command) { return transport.transceive(command); }
            public void close() {
                try { transport.reset(); }
                catch (IOException error) { throw new BIBOException("MicroCard session reset failed", error); }
            }
        };
    }

    byte[] managementKeys() throws IOException {
        if (physicalManagementKeys != null) return physicalManagementKeys.clone();
        byte[] keys = Files.readAllBytes(directory.resolve("keys"));
        if (keys.length != 32) throw new IOException("Invalid simulator management keys");
        return keys;
    }

    public String name() {
        return physicalReader == null ? "MicroCard JCVM host (synthetic ATR)"
            : "pcsc:" + physicalReader;
    }
    public byte[] getAtr() { return new byte[]{0x3b, (byte) 0x80, 0x01, (byte) 0x81}; }

    public byte[] transmit(byte[] command) throws CardException {
        if (physicalReader != null) {
            try (BIBO connection = openBibo()) {
                return connection.transceive(command);
            }
        }
        try { return transport.transceive(command); }
        catch (RuntimeException error) { throw new CardException("MicroCard APDU exchange failed", error); }
    }

    public void reset() throws CardException {
        if (physicalReader != null) return;
        try { transport.reset(); }
        catch (IOException error) { throw new CardException("MicroCard reset failed", error); }
    }

    public void close() {
        if (closed) return;
        closed = true;
        if (transport != null) transport.close();
        if (directory != null) removeDirectory();
    }

    private void removeDirectory() {
        if (directory == null) return;
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        } catch (IOException error) {
            throw new IllegalStateException("Cannot remove temporary NIST card state", error);
        }
    }

    static NistCardTransport unsupportedContactless() {
        return new NistCardTransport() {
            public String name() { return "MicroCard contactless unavailable"; }
            public byte[] getAtr() { throw new UnsupportedOperationException("Contactless is unsupported"); }
            public byte[] transmit(byte[] command) throws CardException {
                throw new CardException("MicroCard host does not implement contactless transport");
            }
            public void reset() throws CardException {
                throw new CardException("MicroCard host does not implement contactless reset");
            }
            public void close() { }
        };
    }
}
