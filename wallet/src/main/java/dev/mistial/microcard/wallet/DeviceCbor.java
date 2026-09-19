package dev.mistial.microcard.wallet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Fixed-field device records; JSON remains a host authoring format. */
final class DeviceCbor {
    private DeviceCbor() {}

    static byte[] managementNames(String first, String second) {
        var output = new ByteArrayOutputStream(134);
        output.write(0x83);
        output.write(1);
        for (String value : new String[]{first, second}) {
            if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"))
                throw new IllegalArgumentException("Invalid management identifier");
            byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length < 24) output.write(0x60 + bytes.length);
            else { output.write(0x78); output.write(bytes.length); }
            output.writeBytes(bytes);
        }
        return output.toByteArray();
    }
}
