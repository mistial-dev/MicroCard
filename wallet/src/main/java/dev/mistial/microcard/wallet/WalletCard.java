package dev.mistial.microcard.wallet;

import apdu4j.core.ResponseAPDU;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.*;
import java.util.*;

final class WalletCard {
    static final byte[] ISD_SEED = Packages.seed(0x11);
    static final Identity PERSONAL = new Identity("wallet-personal", "Personal", "F04D4309C0", "wallet-personal", Packages.seed(0x45));
    static final Identity WORK = new Identity("wallet-work", "Work", "F04D4309C1", "wallet-work", Packages.seed(0x46));
    static final List<Identity> IDENTITIES = List.of(PERSONAL, WORK);

    record Identity(String domain, String label, String aid, String asset, byte[] signerSeed) {
        byte[] aidBytes() { return HexFormat.of().parseHex(aid); }
    }
    record Domain(String id, byte[] incarnation, boolean bound, byte[] signer, int assemblies, int instances, int records) { }

    private final CardConnection card;
    private final Path assets;

    WalletCard(CardConnection card, Path assets) { this.card = card; this.assets = assets; }

    List<Domain> inventory() throws Exception {
        var result = new ArrayList<Domain>();
        int total = -1;
        for (int index = 0; total < 0 || index < total; index++) {
            byte[] raw = card.command(0xE2, new byte[]{(byte)index});
            if (raw.length < 58 || raw[0] != 1 || (raw[2] & 255) != index) throw new IOException("Invalid domain inventory");
            int announced = raw[1] & 255;
            if (announced < 1 || announced > 9 || total >= 0 && total != announced) throw new IOException("Domain inventory changed; retry");
            total = announced;
            int length = raw[3] & 255;
            if (length < 1 || length > 64 || raw.length != 57 + length) throw new IOException("Invalid domain record");
            String id = new String(raw, 4, length, StandardCharsets.US_ASCII);
            int offset = 4 + length;
            byte[] incarnation = Arrays.copyOfRange(raw, offset, offset + 16);
            boolean bound = raw[offset + 16] != 0;
            byte[] signer = bound ? Arrays.copyOfRange(raw, offset + 17, offset + 49) : null;
            result.add(new Domain(id, incarnation, bound, signer, raw[offset + 49] & 255,
                raw[offset + 50] & 255, Byte.toUnsignedInt(raw[offset + 51]) | Byte.toUnsignedInt(raw[offset + 52]) << 8));
        }
        if (!result.getFirst().id().equals("ISD")) throw new IOException("ISD missing from inventory");
        return List.copyOf(result);
    }

    void setup(char[] pin, char[] recovery) throws Exception {
        byte[] pinBytes = asciiSecret(pin, 4, "PIN");
        byte[] recoveryBytes = asciiSecret(recovery, 8, "recovery code");
        try {
            ensureIsd();
            for (Identity identity : IDENTITIES) ensureIdentity(identity, pinBytes, recoveryBytes);
        } finally {
            Arrays.fill(pinBytes, (byte)0); Arrays.fill(recoveryBytes, (byte)0);
        }
    }

    private void upload(String asset, String domain, byte[] incarnation, byte[] seed) throws Exception {
        try {
            Packages.upload(card, Packages.create(assets, asset, domain, incarnation, seed));
        } catch (IOException failure) {
            throw new IOException("Loading " + asset + " into " + domain + ": " + failure.getMessage(), failure);
        }
    }

    private void ensureIsd() throws Exception {
        Domain isd = inventory().getFirst();
        if (!isd.bound()) {
            upload("mscorlib", "ISD", isd.incarnation(), ISD_SEED);
            isd = inventory().getFirst();
        }
        requireSigner(isd, Packages.signerIdentity(ISD_SEED));
        if (isd.assemblies() < 2) upload("cryptography", "ISD", isd.incarnation(), ISD_SEED);
        isd = inventory().getFirst();
        if (isd.assemblies() < 3) upload("security", "ISD", isd.incarnation(), ISD_SEED);
        if (inventory().getFirst().assemblies() < 3) throw new IOException("ISD dependency setup incomplete");
    }

    private void ensureIdentity(Identity identity, byte[] pin, byte[] recovery) throws Exception {
        Domain domain = find(identity.domain()).orElse(null);
        if (domain == null) {
            byte[] incarnation = card.command(0xE0, identity.domain().getBytes(StandardCharsets.US_ASCII));
            if (incarnation.length != 16) throw new IOException("Invalid SSD incarnation");
            domain = find(identity.domain()).orElseThrow();
        }
        if (!domain.bound()) {
            upload(identity.asset(), identity.domain(), domain.incarnation(), identity.signerSeed());
            domain = find(identity.domain()).orElseThrow();
        }
        requireSigner(domain, Packages.signerIdentity(identity.signerSeed()));
        if (domain.assemblies() != 1) throw new IOException(identity.label() + " has unexpected assembly state");
        if (domain.instances() == 0) {
            card.command(0xEC, DeviceCbor.managementNames(identity.domain(), identity.aid()));
            domain = find(identity.domain()).orElseThrow();
        }
        if (domain.instances() != 1) throw new IOException(identity.label() + " has unexpected instance state");
        select(identity);
        byte[] current = process(new byte[]{1}, 0x9000);
        if (current.length == 0) {
            byte[] label = (identity.label() + " identity").getBytes(StandardCharsets.UTF_8);
            byte[] provision = new byte[1 + pin.length + recovery.length + label.length];
            provision[0] = 0; System.arraycopy(pin, 0, provision, 1, pin.length);
            System.arraycopy(recovery, 0, provision, 1 + pin.length, recovery.length);
            System.arraycopy(label, 0, provision, 1 + pin.length + recovery.length, label.length);
            try { process(provision, 0x9000); } finally { Arrays.fill(provision, (byte)0); }
        }
    }

    void select(Identity identity) throws Exception { card.command(0xA4, identity.aidBytes()); }
    byte[] publicData(Identity identity) throws Exception { select(identity); return process(new byte[]{1}, 0x9000); }
    byte[] publicKey(Identity identity) throws Exception { select(identity); return process(new byte[]{2}, 0x9000); }
    int retries(Identity identity) throws Exception { select(identity); return process(new byte[]{4}, 0x9000)[0] & 255; }

    byte[] sign(Identity identity, char[] pin, byte[] challenge, int expectedStatus) throws Exception {
        byte[] pinBytes = asciiSecret(pin, 4, "PIN");
        if (challenge.length < 1 || challenge.length > 194) throw new IllegalArgumentException("Challenge must be 1..194 bytes");
        byte[] command = new byte[1 + pinBytes.length + challenge.length]; command[0] = 3;
        System.arraycopy(pinBytes, 0, command, 1, pinBytes.length); System.arraycopy(challenge, 0, command, 5, challenge.length);
        try { select(identity); return process(command, expectedStatus); }
        finally { Arrays.fill(pinBytes, (byte)0); Arrays.fill(command, (byte)0); }
    }

    boolean recover(Identity identity, char[] recovery, char[] newPin) throws Exception {
        byte[] recoveryBytes = asciiSecret(recovery, 8, "recovery code");
        byte[] pinBytes = asciiSecret(newPin, 4, "PIN");
        byte[] command = new byte[13]; command[0] = 5;
        System.arraycopy(recoveryBytes, 0, command, 1, 8); System.arraycopy(pinBytes, 0, command, 9, 4);
        try { select(identity); return Arrays.equals(process(command, 0x9000), new byte[]{1}); }
        finally { Arrays.fill(recoveryBytes, (byte)0); Arrays.fill(pinBytes, (byte)0); Arrays.fill(command, (byte)0); }
    }

    private byte[] process(byte[] data, int expectedStatus) throws Exception {
        ResponseAPDU response = card.exchange(0x10, data);
        if (response.getSW() != expectedStatus) throw new IOException(String.format("Credential command returned SW=%04X, expected %04X", response.getSW(), expectedStatus));
        return response.getData();
    }

    private Optional<Domain> find(String id) throws Exception { return inventory().stream().filter(item -> item.id().equals(id)).findFirst(); }
    private static void requireSigner(Domain domain, byte[] expected) throws IOException {
        if (!domain.bound() || !MessageDigest.isEqual(domain.signer(), expected)) throw new IOException(domain.id() + " signer does not match this wallet");
    }
    private static byte[] asciiSecret(char[] input, int length, String name) {
        if (input.length != length) throw new IllegalArgumentException(name + " must contain exactly " + length + " ASCII characters");
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) { if (input[i] > 0x7f) throw new IllegalArgumentException(name + " must be ASCII"); result[i] = (byte)input[i]; }
        return result;
    }

    static boolean verifyP256(byte[] rawPublicKey, byte[] message, byte[] signature) throws Exception {
        if (rawPublicKey.length != 65 || rawPublicKey[0] != 4 || signature.length != 64) return false;
        var parameters = AlgorithmParameters.getInstance("EC"); parameters.init(new ECGenParameterSpec("secp256r1"));
        var spec = parameters.getParameterSpec(ECParameterSpec.class);
        var point = new ECPoint(new java.math.BigInteger(1, Arrays.copyOfRange(rawPublicKey, 1, 33)),
            new java.math.BigInteger(1, Arrays.copyOfRange(rawPublicKey, 33, 65)));
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(key); verifier.update(message); return verifier.verify(signature);
    }
}
