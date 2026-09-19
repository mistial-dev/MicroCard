package dev.mistial.microcard.wallet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** MP05 signed descriptor followed by its image. */
final class PackageEnvelope {
    private PackageEnvelope() {}
    static byte[] create(byte[] manifest, byte[] image, byte[] seed) throws IOException {
        byte[] prefix = "MP05MicroCard signed package v5\0".getBytes(StandardCharsets.US_ASCII);
        if ((long)prefix.length + 8 + 32 + 65 + 64 + manifest.length + image.length > 16384)
            throw new IOException("Package exceeds quota");
        if (seed.length != 32) throw new IOException("Invalid seed length");
        var output = new ByteArrayOutputStream();
        output.write(prefix);
        output.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(manifest.length).putInt(image.length).array());
        output.write(manifest);
        try { output.write(MessageDigest.getInstance("SHA-256").digest(image)); }
        catch (NoSuchAlgorithmException e) { throw new IOException(e); }
        output.write(Packages.publicKey(seed));
        output.write(Packages.signature(seed, output.toByteArray()));
        output.write(image);
        return output.toByteArray();
    }
}
