package dev.mistial.microcard.wallet;

import com.google.gson.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;
import java.util.*;

/** MP04 canonical envelope. See docs/PROTOCOL.md; runtime verification remains authoritative. */
final class Packages {
    static final Gson JSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    static byte[] seed(int value) { byte[] result = new byte[32]; Arrays.fill(result, (byte)value); return result; }
    static final org.bouncycastle.asn1.x9.X9ECParameters CURVE = SECNamedCurves.getByName("secp256r1");

    /** The uncompressed SEC1 point a package carries for its signer. */
    static byte[] publicKey(byte[] seed) { return point(seed).getEncoded(false); }

    /** The identity a domain binds to, which is the digest of that point. */
    static byte[] signerIdentity(byte[] seed) throws IOException {
        try { return MessageDigest.getInstance("SHA-256").digest(publicKey(seed)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IOException(e); }
    }

    private static ECPoint point(byte[] seed) { return CURVE.getG().multiply(scalar(seed)).normalize(); }

    private static BigInteger scalar(byte[] seed) {
        BigInteger d = new BigInteger(1, seed);
        if (d.signum() <= 0 || d.compareTo(CURVE.getN()) >= 0) throw new IllegalArgumentException("seed is not a P-256 private scalar");
        return d;
    }

    /**
     * Deterministic ECDSA over SHA-256, RFC 6979, as fixed-width r and s.
     *
     * The card accepts only the low of the two signatures that verify, so that one signed
     * package has one encoding and therefore one digest and one registry identity.
     */
    static byte[] signature(byte[] seed, byte[] message) throws IOException {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(scalar(seed), new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN())));
        byte[] digest;
        try { digest = MessageDigest.getInstance("SHA-256").digest(message); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IOException(e); }
        BigInteger[] parts = signer.generateSignature(digest);
        BigInteger r = parts[0], s = parts[1];
        if (s.compareTo(CURVE.getN().shiftRight(1)) > 0) s = CURVE.getN().subtract(s);
        byte[] out = new byte[64];
        fixedWidth(r, out, 0); fixedWidth(s, out, 32);
        return out;
    }

    private static void fixedWidth(BigInteger value, byte[] destination, int offset) {
        byte[] bytes = value.toByteArray();
        int start = bytes.length > 32 ? bytes.length - 32 : 0;
        int length = bytes.length - start;
        System.arraycopy(bytes, start, destination, offset + 32 - length, length);
    }

    static byte[] create(Path assets, String stem, String domain, byte[] incarnation, byte[] seed) throws IOException {
        JsonObject generated = JsonParser.parseString(Files.readString(assets.resolve(stem + ".json"))).getAsJsonObject();
        return create(Files.readAllBytes(assets.resolve(stem + ".mca")), generated, domain, incarnation, seed);
    }

    static byte[] create(byte[] image, JsonObject generated, String domain, byte[] incarnation, byte[] seed) throws IOException {
        if (incarnation.length != 16 || seed.length != 32) throw new IllegalArgumentException("Invalid package identity");
        JsonObject manifest = new JsonObject();
        manifest.addProperty("domain", domain);
        JsonArray inc = new JsonArray(); for (byte b : incarnation) inc.add(b & 255);
        manifest.add("incarnation", inc);
        for (String name : List.of("assembly", "assembly_version")) manifest.add(name, generated.get(name));
        manifest.addProperty("version", 1);
        manifest.add("export", generated.get("export"));
        JsonArray entryPoints = new JsonArray();
        for (JsonElement element : generated.getAsJsonArray("entry_points")) {
            JsonObject source = element.getAsJsonObject(); JsonObject entry = new JsonObject();
            for (String name : List.of("aid", "process", "install", "uninstall", "select", "deselect"))
                entry.add(name, source.has(name) ? source.get(name) : JsonNull.INSTANCE);
            entryPoints.add(entry);
        }
        manifest.add("entry_points", entryPoints);
        for (String name : List.of("dependencies", "capabilities", "storage")) manifest.add(name, generated.get(name));
        JsonObject limits = new JsonObject();
        limits.addProperty("arena", 16384); limits.addProperty("stack", 256);
        limits.addProperty("frames", 32); limits.addProperty("instructions", 100000);
        manifest.add("limits", limits);
        byte[] meta = JSON.toJson(manifest).getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write("MP04MicroCard signed package v4\0".getBytes(StandardCharsets.US_ASCII));
        message.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(meta.length).putInt(image.length).array());
        message.write(meta); message.write(image); message.write(publicKey(seed));
        message.write(signature(seed, message.toByteArray()));
        if (message.size() > 16384) throw new IOException("Package exceeds device bound");
        return message.toByteArray();
    }

    static void upload(CardConnection card, byte[] bytes) throws Exception {
        upload(card, bytes, 0x9000);
    }

    static void upload(CardConnection card, byte[] bytes, int expectedStatus) throws Exception {
        card.command(0xE6, new byte[0]);
        for (int offset = 0; offset < bytes.length; offset += 192) {
            int size = Math.min(192, bytes.length - offset);
            byte[] chunk = ByteBuffer.allocate(size + 4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(offset).put(bytes, offset, size).array();
            card.command(0xE8, chunk);
        }
        var response = card.exchange(0xEA, new byte[0]);
        if (response.getSW() != expectedStatus) throw new IOException(String.format(
            "Package activation returned SW=%04X, expected %04X", response.getSW(), expectedStatus));
    }
}
