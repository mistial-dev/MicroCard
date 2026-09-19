package dev.mistial.microcard.wallet;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** Fixed-field device manifests using one restricted CBOR writer. */
final class ManifestCbor {
    private ManifestCbor() {}

    static byte[] encodeJcvm(JsonObject value) {
        if (!value.keySet().equals(java.util.Set.of("domain", "incarnation", "package", "package_version", "version", "limits")))
            throw new IllegalArgumentException("Invalid JCVM manifest fields");
        byte[] domain = hex(value.get("domain"), 5, 16), incarnation = hex(value.get("incarnation"), 16, 16),
            aid = hex(value.get("package"), 5, 16);
        var version = value.getAsJsonArray("package_version");
        if (version.size() != 2) throw new IllegalArgumentException("Invalid package version");
        long major = unsigned(version.get(0), 0, 255), minor = unsigned(version.get(1), 0, 255);
        long rollback = unsigned(value.get("version"), 1, 0xffffffffL);
        var limits = value.getAsJsonObject("limits");
        if (!limits.keySet().equals(java.util.Set.of("heap_bytes", "frame_words", "buffer_bytes", "budget")))
            throw new IllegalArgumentException("Invalid JCVM limits");
        long heap = unsigned(limits.get("heap_bytes"), 512, 65536), frames = unsigned(limits.get("frame_words"), 8, 8192),
            buffer = unsigned(limits.get("buffer_bytes"), 261, 261), budget = unsigned(limits.get("budget"), 1, 1000000);
        if (heap % 2 != 0) throw new IllegalArgumentException("Heap must be even");
        Object[] record = {1L, 1L, domain, incarnation, aid, new Object[]{major, minor}, rollback, new Object[]{heap, frames, buffer, budget}};
        var output = new ByteArrayOutputStream(); write(output, record); return output.toByteArray();
    }

    private static long unsigned(JsonElement value, long minimum, long maximum) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber() || !value.getAsString().matches("[0-9]+"))
            throw new IllegalArgumentException("Integer required");
        final long result;
        try { result = value.getAsBigDecimal().longValueExact(); }
        catch (ArithmeticException e) { throw new IllegalArgumentException("Integer required", e); }
        if (result < minimum || result > maximum) throw new IllegalArgumentException("Integer outside profile");
        return result;
    }

    private static byte[] hex(JsonElement value, int minimum, int maximum) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) throw new IllegalArgumentException("Hex string required");
        byte[] bytes = HexFormat.of().parseHex(value.getAsString());
        if (bytes.length < minimum || bytes.length > maximum) throw new IllegalArgumentException("Invalid binary length");
        return bytes;
    }

    private static Object integer(JsonElement value) { return value.isJsonNull() ? null : value.getAsLong(); }
    private static Object[] version(JsonElement value) {
        if (value.isJsonNull()) return null;
        var array = value.getAsJsonArray();
        if (array.size() != 4) throw new IllegalArgumentException("Invalid version");
        return new Object[]{integer(array.get(0)), integer(array.get(1)), integer(array.get(2)), integer(array.get(3))};
    }
    private static byte[] binary(JsonElement value, int size) {
        if (value.isJsonNull()) return null;
        var array = value.getAsJsonArray();
        if (array.size() != size) throw new IllegalArgumentException("Invalid binary field length");
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            int b = array.get(i).getAsInt();
            if (b < 0 || b > 255) throw new IllegalArgumentException("Invalid byte");
            bytes[i] = (byte)b;
        }
        return bytes;
    }
    static byte[] encode(JsonObject value) {
        var entries = value.getAsJsonArray("entry_points");
        if (entries.size() > 4) throw new IllegalArgumentException("Too many entries");
        Object[] entryRecords = new Object[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            var e = entries.get(i).getAsJsonObject();
            String aid = e.get("aid").getAsString();
            if (!aid.matches("(?:[0-9A-F]{2}){5,16}")) throw new IllegalArgumentException("Invalid AID");
            entryRecords[i] = new Object[]{HexFormat.of().parseHex(aid), integer(e.get("process")), integer(e.get("install")),
                integer(e.get("uninstall")), integer(e.get("select")), integer(e.get("deselect"))};
        }
        var dependencies = value.getAsJsonArray("dependencies");
        if (dependencies.size() > 16) throw new IllegalArgumentException("Too many dependencies");
        Object[] dependencyRecords = new Object[dependencies.size()];
        for (int i = 0; i < dependencies.size(); i++) {
            var d = dependencies.get(i).getAsJsonObject(); var ranges = d.getAsJsonArray("ranges");
            if (ranges.size() < 1 || ranges.size() > 8) throw new IllegalArgumentException("Invalid ranges");
            Object[] rangeRecords = new Object[ranges.size()];
            for (int j = 0; j < ranges.size(); j++) {
                var r = ranges.get(j).getAsJsonObject();
                rangeRecords[j] = new Object[]{version(r.get("min")), r.get("min_inclusive").getAsBoolean(),
                    version(r.get("max")), r.get("max_inclusive").getAsBoolean()};
            }
            dependencyRecords[i] = new Object[]{d.get("assembly").getAsString(), rangeRecords, integer(d.get("package_version")),
                binary(d.get("signer"), 32), binary(d.get("digest"), 32), integer(d.get("scope"))};
        }
        var storage = value.getAsJsonArray("storage");
        if (storage.size() > 64) throw new IllegalArgumentException("Too many storage declarations");
        Object[] storageRecords = new Object[storage.size()];
        for (int i = 0; i < storage.size(); i++) {
            var s = storage.get(i).getAsJsonObject();
            storageRecords[i] = new Object[]{integer(s.get("key")), integer(s.get("kind")), integer(s.get("max_bytes"))};
        }
        var export = value.getAsJsonObject("export"); var limits = value.getAsJsonObject("limits");
        int capabilities = value.getAsJsonArray("capabilities").size();
        if (capabilities > 35) throw new IllegalArgumentException("Too many capabilities");
        Object[] record = {1L, value.get("domain").getAsString(), binary(value.get("incarnation"), 16),
            value.get("assembly").getAsString(), version(value.get("assembly_version")), integer(value.get("version")),
            new Object[]{integer(export.get("access")), binary(export.get("key"), 32)}, entryRecords, dependencyRecords,
            binary(value.get("capabilities"), capabilities), storageRecords,
            new Object[]{integer(limits.get("arena")), integer(limits.get("stack")), integer(limits.get("frames")), integer(limits.get("instructions"))}};
        var output = new ByteArrayOutputStream(); write(output, record);
        if (output.size() > 16384) throw new IllegalArgumentException("Manifest quota exceeded");
        return output.toByteArray();
    }
    private static void argument(ByteArrayOutputStream output, int major, long value) {
        if (value < 0) throw new IllegalArgumentException("Unsigned value required");
        int width = value < 24 ? 0 : value <= 255 ? 1 : value <= 65535 ? 2 : value <= 0xffffffffL ? 4 : 8;
        int additional = width == 0 ? (int)value : width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27;
        output.write((major << 5) | additional);
        for (int i = width - 1; i >= 0; i--) output.write((int)(value >>> (8 * i)) & 255);
    }
    private static void write(ByteArrayOutputStream output, Object value) {
        if (value == null) output.write(0xf6);
        else if (value instanceof Boolean b) output.write(b ? 0xf5 : 0xf4);
        else if (value instanceof Long n) argument(output, 0, n);
        else if (value instanceof byte[] bytes) { argument(output, 2, bytes.length); output.writeBytes(bytes); }
        else if (value instanceof String text) {
            if (!text.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")) throw new IllegalArgumentException("Invalid identifier");
            byte[] bytes = text.getBytes(StandardCharsets.US_ASCII); argument(output, 3, bytes.length); output.writeBytes(bytes);
        } else if (value instanceof Object[] array) { argument(output, 4, array.length); for (Object item : array) write(output, item); }
        else throw new IllegalArgumentException("Unsupported CBOR value");
    }
}
