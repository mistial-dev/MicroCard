package dev.mistial.microcard.wallet;

import com.google.gson.*;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;
import java.util.*;

/** MP03 canonical envelope. See docs/PROTOCOL.md; runtime verification remains authoritative. */
final class Packages {
    static final Gson JSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    static byte[] seed(int value) { byte[] result = new byte[32]; Arrays.fill(result, (byte)value); return result; }
    static byte[] publicKey(byte[] seed) { return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded(); }

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
        var key = new Ed25519PrivateKeyParameters(seed, 0);
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write("MP03MicroCard signed package v3\0".getBytes(StandardCharsets.US_ASCII));
        message.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(meta.length).putInt(image.length).array());
        message.write(meta); message.write(image); message.write(key.generatePublicKey().getEncoded());
        byte[] unsigned = message.toByteArray();
        var signer = new Ed25519Signer(); signer.init(true, key); signer.update(unsigned, 0, unsigned.length);
        message.write(signer.generateSignature());
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
