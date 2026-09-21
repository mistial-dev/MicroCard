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
            // The card advertises i=71, so open in S16 directly and take every protection
            // it offers, including response encryption.
            session.openSecureChannel(cardKeys, GPSecureChannelVersion.valueOf(3, 0x71), null,
                EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC,
                    GPSession.APDUMode.RMAC, GPSession.APDUMode.RENC));
        } catch (Exception error) { transport.close(); throw error; }
    }

    ResponseAPDU exchange(int ins, byte[] data) throws Exception {
        if (data.length > 200) throw new IllegalArgumentException("Command exceeds the wallet short-APDU bound");
        ResponseAPDU response = session.transmit(new CommandAPDU(0x80, ins, 0, 0, data));
        if (trace) System.err.printf("SCP03/33 INS=%02X input=%d bytes [redacted] output=%d bytes SW=%04X%n",
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
        return new SimulatorTransport(binary, keys, state, SimulatorTransport.Engine.MC04);
    }

    static BIBO reader(String name) throws Exception {
        return PcscTransport.open(name);
    }

}
