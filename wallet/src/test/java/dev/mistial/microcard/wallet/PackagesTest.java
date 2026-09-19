package dev.mistial.microcard.wallet;

import com.google.gson.JsonParser;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import java.math.BigInteger;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

final class PackagesTest {
    private static final byte[] PREFIX = "MP04MicroCard signed package v4\0".getBytes(StandardCharsets.US_ASCII);

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
        assertEquals(first.length, PREFIX.length + 8 + metadataLength + imageLength + 65 + 64);
    }

    /** An independent verifier, so the packager is checked by something other than itself. */
    private static boolean verifies(byte[] packageBytes) throws Exception {
        if (packageBytes.length < 129) return false;
        int publicKeyOffset = packageBytes.length - 129;
        int signatureOffset = packageBytes.length - 64;
        var curve = SECNamedCurves.getByName("secp256r1");
        org.bouncycastle.math.ec.ECPoint point;
        try {
            point = curve.getCurve().decodePoint(Arrays.copyOfRange(packageBytes, publicKeyOffset, signatureOffset));
        } catch (IllegalArgumentException invalidPoint) {
            return false;
        }
        var verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(point, new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN())));
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(Arrays.copyOfRange(packageBytes, 0, signatureOffset));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(packageBytes, signatureOffset, signatureOffset + 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(packageBytes, signatureOffset + 32, packageBytes.length));
        // The card accepts only the low form, so the packager has to have produced it.
        if (s.compareTo(curve.getN().shiftRight(1)) > 0) return false;
        return verifier.verifySignature(digest, r, s);
    }
}
