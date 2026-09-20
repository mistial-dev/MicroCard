package dev.mistial.tools.openfips201.nist;

import com.tvec.utility.configuration.Configuration;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.provisioning.AdminTlv;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.cert.*;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/** Loads the published P-256 key fixtures without replacing the NIST expectations. */
final class MicroCardNistProfile {
    public static void main(String[] args) throws Exception {
        var profile = load(new Configuration(Path.of(args[0]).toFile()), Path.of(args[1]));
        try (var card = new MicroCardNistTransport()) {
            ConformanceProvisioner.provision(card::openBibo, scp(card), profile, System.out);
            card.saveSeed(Path.of(args[2]));
        }
    }

    static ScpConfig scp(MicroCardNistTransport contact) throws Exception {
        byte[] keys = contact.managementKeys();
        try {
            return new ScpConfig(ScpConfig.Mode.SCP03, 1, Arrays.copyOfRange(keys, 0, 16),
                Arrays.copyOfRange(keys, 16, 32), Arrays.copyOfRange(keys, 0, 16));
        } finally { Arrays.fill(keys, (byte) 0); }
    }

    static ConformancePackage load(Configuration config, Path upstream) throws Exception {
        byte[] pin = pin(value(config, "PIN_VALID"));
        byte[] puk = pin(value(config, "PUK_VALID"));
        if (!value(config, "KEY_ALGORITHMS_CARD_MANAGEMENT").equals("08"))
            throw new IllegalArgumentException("This profile requires AES-128 management");
        byte[] management = HexFormat.of().parseHex(value(config, "keytypealgorithmkeys:KEY_9B_08"));
        if (management.length != 16) throw new IllegalArgumentException("Invalid AES-128 test key");
        String[] roles = {"AUTHENTICATION", "DIGITAL_SIGNATURE", "KEY_MANAGEMENT", "CARD_AUTHENTICATION"};
        String[] slots = {"9A", "9C", "9D", "9E"};
        int[] ids = {0x05, 0x0a, 0x0b, 0x01};
        int[] access = {1, 2, 1, 0x7f};
        var objects = new ArrayList<ConformancePackage.DataObject>();
        var keys = new ArrayList<ConformancePackage.KeyMaterial>();
        for (int i = 0; i < slots.length; i++) {
            String slot = slots[i];
            if (!value(config, "KEY_ALGORITHMS_" + roles[i]).equals("11"))
                throw new IllegalArgumentException("Unsupported configured algorithm for " + slot);
            byte[] pem = value(config, "keytypealgorithmkeys:KEY_" + slot + "_11").getBytes(StandardCharsets.US_ASCII);
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
            if (!(certificate.getPublicKey() instanceof ECPublicKey ec) || ec.getParams().getOrder().bitLength() != 256)
                throw new IllegalArgumentException("Expected a P-256 certificate for " + slot);
            Path keyFile = upstream.resolve("tools/piv_test_runner/test_keys/" + slot + "/"
                + (i == 0 ? "11_private.pem" : "11.pem"));
            KeyPair pair = null;
            try (var reader = new PEMParser(Files.newBufferedReader(keyFile))) {
                Object item;
                while ((item = reader.readObject()) != null) {
                    if (item instanceof PEMKeyPair key) pair = new JcaPEMKeyConverter().getKeyPair(key);
                }
            }
            if (pair == null || !Arrays.equals(pair.getPublic().getEncoded(), certificate.getPublicKey().getEncoded()))
                throw new IllegalArgumentException("Test private key does not match configured certificate for " + slot);
            keys.add(new ConformancePackage.KeyMaterial((byte) Integer.parseInt(slot, 16), slot,
                (byte) 0x11, (byte) (i == 2 ? 2 : 4), (byte) 0x10, (byte) access[i],
                (byte) (i == 3 ? 0x7f : access[i] | 8), pair.getPrivate(), certificate));
            objects.add(new ConformancePackage.DataObject(new byte[]{0x5f, (byte) 0xc1, (byte) ids[i]},
                slot + " certificate", (byte) 0x7f, (byte) (i == 3 ? 0x7f : 8),
                ConformancePackage.PutForm.TAG_LIST, AdminTlv.concat(AdminTlv.tlv(0x70, certificate.getEncoded()),
                    new byte[]{0x71, 1, 0, (byte) 0xfe, 0})));
        }
        return new ConformancePackage("upstream-p256-keys", upstream, pin, puk,
            new ConformancePackage.ManagementKeyMaterial((byte) 8, management), objects, keys);
    }

    private static String value(Configuration config, String name) {
        var entry = config.getEntry("testing:" + name);
        if (entry == null || entry.getValueString() == null) throw new IllegalArgumentException("Missing " + name);
        return entry.getValueString().toString().trim();
    }

    private static byte[] pin(String text) {
        if (!text.matches("[0-9]{6,8}")) throw new IllegalArgumentException("Invalid configured PIN or PUK");
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) 0xff);
        System.arraycopy(text.getBytes(StandardCharsets.US_ASCII), 0, bytes, 0, text.length());
        return bytes;
    }
}
