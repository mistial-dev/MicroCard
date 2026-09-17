package dev.mistial.microcard.wallet;

import com.google.gson.JsonParser;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

final class PackagesTest {
    private static final byte[] PREFIX = "MP03MicroCard signed package v3\0".getBytes(StandardCharsets.US_ASCII);

    @Test
    void canonicalPackageCoversEveryByteAndIsDeterministic() throws Exception {
        byte[] image = new byte[]{0x4d, 0x43, 0x30, 0x34, 1, 2, 3};
        var metadata = JsonParser.parseString("""
            {"assembly":"Example","assembly_version":[0,1,0,0],"export":{"access":0,"signer":null},
             "entry_points":[{"process":7,"aid":"F04D430001"}],"dependencies":[],"capabilities":[2],"storage":[]}
            """).getAsJsonObject();
        byte[] seed = Packages.seed(0x33);
        byte[] incarnation = new byte[16];
        byte[] first = Packages.create(image, metadata, "domain", incarnation, seed);
        byte[] second = Packages.create(image, metadata, "domain", incarnation, seed);
        assertArrayEquals(first, second);
        assertTrue(Arrays.equals(PREFIX, Arrays.copyOf(first, PREFIX.length)));
        assertTrue(verifies(first));

        for (int index : new int[]{0, PREFIX.length, first.length / 2, first.length - 65}) {
            byte[] modified = first.clone();
            modified[index] ^= 1;
            assertFalse(verifies(modified), "modified byte " + index + " remained valid");
        }

        ByteBuffer lengths = ByteBuffer.wrap(first, PREFIX.length, 8).order(ByteOrder.LITTLE_ENDIAN);
        int metadataLength = lengths.getInt();
        int imageLength = lengths.getInt();
        assertEquals(first.length, PREFIX.length + 8 + metadataLength + imageLength + 32 + 64);
    }

    private static boolean verifies(byte[] packageBytes) {
        if (packageBytes.length < 96) return false;
        int publicKeyOffset = packageBytes.length - 96;
        int signatureOffset = packageBytes.length - 64;
        var verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(packageBytes, publicKeyOffset));
        verifier.update(packageBytes, 0, signatureOffset);
        return verifier.verifySignature(Arrays.copyOfRange(packageBytes, signatureOffset, packageBytes.length));
    }
}
