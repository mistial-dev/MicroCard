package dev.mistial.microcard.wallet;

import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class DeviceCborTest {
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
