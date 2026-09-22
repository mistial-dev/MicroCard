package dev.mistial.microcard.wallet;

import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class DeviceCborTest {
    @Test
    void signedEnvelopeMatchesIndependentVector() throws Exception {
        Path path = Path.of(System.getProperty("basedir"), "../format/package-envelope-v5.json");
        var vector = JsonParser.parseString(Files.readString(path)).getAsJsonObject();
        var hex = HexFormat.of();
        assertArrayEquals(hex.parseHex(vector.get("package").getAsString()), PackageEnvelope.create(
            hex.parseHex(vector.get("manifest").getAsString()), hex.parseHex(vector.get("image").getAsString()),
            hex.parseHex(vector.get("seed").getAsString())));
        byte[] image = new byte[17 * 1024], seed = hex.parseHex(vector.get("seed").getAsString());
        assertThrows(java.io.IOException.class, () -> PackageEnvelope.create(new byte[0], image, seed));
        byte[] larger = PackageEnvelope.create(new byte[0], image, seed, 60 * 1024);
        assertArrayEquals(image, java.util.Arrays.copyOfRange(larger, larger.length - image.length, larger.length));
    }

    @Test
    void manifestRecordsMatchSharedVectors() throws Exception {
        Path vectors = Path.of(System.getProperty("basedir"), "../format/manifest-cbor-v1.json");
        for (var item : JsonParser.parseString(Files.readString(vectors)).getAsJsonArray()) {
            var vector = item.getAsJsonObject();
            assertArrayEquals(HexFormat.of().parseHex(vector.get("hex").getAsString()),
                ManifestCbor.encode(vector.getAsJsonObject("manifest")));
        }
    }

    @Test
    void managementRecordsMatchSharedVectors() throws Exception {
        Path vectors = Path.of(System.getProperty("basedir"), "../format/management-names-v1.json");
        for (var item : JsonParser.parseString(Files.readString(vectors)).getAsJsonArray()) {
            var vector = item.getAsJsonObject();
            assertArrayEquals(HexFormat.of().parseHex(vector.get("hex").getAsString()),
                DeviceCbor.managementNames(vector.get("first").getAsString(), vector.get("second").getAsString()));
        }
        for (String value : new String[]{"", "x".repeat(65), "bad/name", "é", null})
            assertThrows(IllegalArgumentException.class, () -> DeviceCbor.managementNames(value, "Counter"));
    }
}
