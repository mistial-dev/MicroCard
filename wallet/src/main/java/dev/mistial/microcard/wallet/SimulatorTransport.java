package dev.mistial.microcard.wallet;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import java.io.*;
import java.nio.file.Path;
import java.util.concurrent.*;

/** Binary simulator transport shared by the wallet and external conformance runners. */
public final class SimulatorTransport implements BIBO {
    public enum Engine {
        MC04("serve-binary"), JCVM("serve-jcvm-managed-binary");
        private final String command;
        Engine(String command) { this.command = command; }
    }

    private final ProcessBuilder builder;
    private final ExecutorService reads = Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
    private Process process;
    private InputStream input;
    private OutputStream output;
    private boolean closed;

    public SimulatorTransport(Path binary, Path keys, Path state, Engine engine) throws IOException {
        builder = new ProcessBuilder(binary.toAbsolutePath().toString(), engine.command,
            keys.toAbsolutePath().toString(), state.toAbsolutePath().toString())
            .redirectError(ProcessBuilder.Redirect.INHERIT);
        try { start(); }
        catch (IOException error) { reads.shutdownNow(); throw error; }
    }

    private void start() throws IOException {
        process = builder.start();
        input = process.getInputStream(); output = process.getOutputStream();
    }

    public synchronized byte[] transceive(byte[] command) {
        if (closed) throw new BIBOException("Simulator transport is closed");
        if (command.length < 4 || command.length > 261)
            throw new BIBOException("Only short APDUs are supported");
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

    /** Reopen the same authenticated storage, clearing volatile selection and security state. */
    public synchronized void reset() throws IOException {
        if (closed) throw new IOException("Simulator transport is closed");
        try {
            stop();
            start();
        } catch (IOException error) { close(); throw error; }
    }

    private void stop() throws IOException {
        if (process == null) return;
        try {
            try { output.close(); } catch (IOException ignored) { }
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                if (!process.waitFor(3, TimeUnit.SECONDS))
                    throw new IOException("Simulator did not stop; storage cannot be reopened");
            }
            input.close();
        } catch (InterruptedException error) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while stopping simulator", error);
        }
    }

    public synchronized void close() {
        if (closed) return;
        closed = true;
        reads.shutdownNow();
        try { stop(); } catch (IOException ignored) { }
    }
}
