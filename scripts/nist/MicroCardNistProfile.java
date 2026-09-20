package dev.mistial.tools.openfips201.nist;

import com.tvec.utility.configuration.Configuration;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.PlainPivSession;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import dev.mistial.tools.openfips201.provisioning.IcamCardFolder;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.provisioning.AdminTlv;
import dev.mistial.tools.openfips201.provisioning.ConformancePackage;
import dev.mistial.tools.openfips201.provisioning.ConformanceProvisioner;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import javax.crypto.KeyAgreement;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/** Loads the published P-256 key fixtures without replacing the NIST expectations. */
final class MicroCardNistProfile {
    public static void main(String[] args) throws Exception {
        var config = new Configuration(Path.of(args[0]).toFile());
        var profile = args.length == 4 ? loadIdentity(config, Path.of(args[3])) : load(config, Path.of(args[1]));
        try (var card = new MicroCardNistTransport()) {
            // The generic upstream provisioner enables external authentication only.
            // NIST management vectors require mutual authentication as well.
            var objectsAndKeys = new ConformancePackage(profile.credentialId, profile.sourceDirectory,
                profile.pin, profile.puk, null, profile.dataObjects, profile.keys);
            ConformanceProvisioner.provision(card::openBibo, scp(card), objectsAndKeys, System.out);
            try (var transport = CardTransport.own(card.openBibo());
                 var session = transport.openGlobalPlatformSession(GlobalPlatformSession.PIV_AID, scp(card))) {
                byte[] definition = StandardCardProfile.managementKeyDefinition(profile.managementKey.algorithm);
                definition[definition.length - 1] |= 0x08; // ATTR_PERMIT_MUTUAL
                expect(session.transmit(new CommandAPDU(0x80, 0xdb, 0xff, 0xff, definition)), "Create mutual management key");
                byte[] update = AdminTlv.concat(AdminTlv.tlv(0x80, new byte[]{profile.managementKey.algorithm}),
                    StandardCardProfile.keyUpdateData(profile.managementKey.key));
                expect(session.transmit(new CommandAPDU(0x80, 0x25, 1, 0x9b, update)), "Import management key");
            }
            verifyKeyManagementEcdh(card, profile);
            card.saveSeed(Path.of(args[2]));
        }
    }

    private static void verifyKeyManagementEcdh(MicroCardNistTransport card, ConformancePackage profile)
            throws Exception {
        X509Certificate certificate = null;
        for (var key : profile.keys) {
            if (key.slot == (byte) 0x9d) certificate = key.certificate;
        }
        verifyKeyManagementCertificate(certificate);
        ECPublicKey cardPublic = (ECPublicKey) certificate.getPublicKey();
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var peer = generator.generateKeyPair();
        byte[] point = encodePoint((ECPublicKey) peer.getPublic());
        byte[] request = AdminTlv.tlv(0x7c,
            AdminTlv.concat(AdminTlv.tlv(0x85, point), AdminTlv.tlv(0x82, new byte[0])));
        try (var session = PlainPivSession.open(card::openBibo, GlobalPlatformSession.PIV_AID)) {
            expect(session.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x80, profile.pin)),
                "Verify PIN for slot 9D ECDH");
            var response = session.transmit(new CommandAPDU(0x00, 0x87, 0x11, 0x9d, request, 256));
            expect(response, "P-256 slot 9D ECDH");
            byte[] value = response.getData();
            if (value.length != 36 || value[0] != 0x7c || value[1] != 0x22
                    || value[2] != (byte) 0x82 || value[3] != 0x20)
                throw new IllegalStateException("P-256 slot 9D returned malformed ECDH output");
            var agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(peer.getPrivate());
            agreement.doPhase(cardPublic, true);
            if (!Arrays.equals(agreement.generateSecret(), Arrays.copyOfRange(value, 4, 36)))
                throw new IllegalStateException("P-256 slot 9D private key does not match its certificate");
        }
        System.out.println("Verified SP 800-73/78 slot 9D certificate profile and ECDH binding");
    }

    private static void verifyKeyManagementCertificate(X509Certificate certificate) throws Exception {
        if (certificate == null || !(certificate.getPublicKey() instanceof ECPublicKey ec)
                || ec.getParams().getOrder().bitLength() != 256)
            throw new IllegalArgumentException("Slot 9D certificate must contain a P-256 key");
        boolean[] usage = certificate.getKeyUsage();
        if (usage == null || usage.length <= 4 || !usage[4])
            throw new IllegalArgumentException("Slot 9D certificate must permit key agreement");
        for (int i = 0; i < usage.length; i++) {
            if (i != 4 && usage[i])
                throw new IllegalArgumentException("Slot 9D certificate has an incompatible key usage");
        }
        if (certificate.getBasicConstraints() >= 0)
            throw new IllegalArgumentException("Slot 9D certificate must not be a CA certificate");

        var policies = CertificatePolicies.getInstance(extension(certificate, Extension.certificatePolicies));
        if (policies.getPolicyInformation().length != 1
                || !"2.16.840.1.101.3.2.1.3.6".equals(
                    policies.getPolicyInformation()[0].getPolicyIdentifier().getId()))
            throw new IllegalArgumentException("Slot 9D certificate has the wrong PIV policy");

        var crls = CRLDistPoint.getInstance(extension(certificate, Extension.cRLDistributionPoints));
        boolean validCrl = false;
        for (var point : crls.getDistributionPoints()) {
            if (point.getDistributionPoint() == null
                    || point.getDistributionPoint().getType() != DistributionPointName.FULL_NAME) continue;
            for (var name : GeneralNames.getInstance(point.getDistributionPoint().getName()).getNames()) {
                validCrl |= httpUri(name, ".crl");
            }
        }
        if (!validCrl) throw new IllegalArgumentException("Slot 9D certificate lacks an HTTP CRL URI");

        var aia = AuthorityInformationAccess.getInstance(extension(certificate, Extension.authorityInfoAccess));
        boolean validIssuer = false;
        for (var description : aia.getAccessDescriptions()) {
            validIssuer |= description.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)
                && httpUri(description.getAccessLocation(), ".p7c");
        }
        if (!validIssuer)
            throw new IllegalArgumentException("Slot 9D certificate lacks an HTTP CA Issuers URI");
    }

    private static ASN1Primitive extension(X509Certificate certificate, ASN1ObjectIdentifier oid)
            throws Exception {
        byte[] encoded = certificate.getExtensionValue(oid.getId());
        if (encoded == null) throw new IllegalArgumentException("Slot 9D certificate lacks " + oid);
        return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(encoded).getOctets());
    }

    private static boolean httpUri(GeneralName name, String suffix) {
        if (name.getTagNo() != GeneralName.uniformResourceIdentifier) return false;
        String uri = name.getName().toString().toLowerCase(Locale.ROOT);
        return (uri.startsWith("http://") || uri.startsWith("https://"))
            && (suffix == null || uri.endsWith(suffix));
    }

    private static byte[] encodePoint(ECPublicKey key) {
        byte[] result = new byte[65];
        result[0] = 0x04;
        copyCoordinate(key.getW().getAffineX().toByteArray(), result, 1);
        copyCoordinate(key.getW().getAffineY().toByteArray(), result, 33);
        return result;
    }

    private static void copyCoordinate(byte[] source, byte[] destination, int offset) {
        int count = Math.min(32, source.length);
        System.arraycopy(source, source.length - count, destination, offset + 32 - count, count);
    }

    private static void expect(ResponseAPDU response, String operation) {
        if (response.getSW() != 0x9000)
            throw new IllegalStateException(String.format("%s failed: %04X", operation, response.getSW()));
    }

    static ScpConfig scp(MicroCardNistTransport contact) throws Exception {
        byte[] keys = contact.managementKeys();
        try {
            return new ScpConfig(ScpConfig.Mode.SCP03, 1, Arrays.copyOfRange(keys, 0, 16),
                Arrays.copyOfRange(keys, 16, 32), Arrays.copyOfRange(keys, 0, 16));
        } finally { Arrays.fill(keys, (byte) 0); }
    }

    private static ConformancePackage loadIdentity(Configuration config, Path directory) throws Exception {
        var original = IcamCardFolder.load(directory, "microcard-test".toCharArray());
        if (original.keys.size() != 4) throw new IllegalArgumentException("Expected four P-256 identity keys");
        for (var key : original.keys) {
            if (key.algorithm != 0x11) throw new IllegalArgumentException("Unsupported identity key algorithm");
            String slot = String.format("%02X", key.slot & 0xff);
            byte[] pem = value(config, "keytypealgorithmkeys:KEY_" + slot + "_11").getBytes(StandardCharsets.US_ASCII);
            var expected = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem));
            if (!Arrays.equals(expected.getEncoded(), key.certificate.getEncoded()))
                throw new IllegalArgumentException("Identity certificate differs from NIST configuration: " + slot);
        }
        return new ConformancePackage(original.credentialId, directory,
            pin(value(config, "PIN_VALID")), pin(value(config, "PUK_VALID")),
            managementKey(config), original.dataObjects, original.keys);
    }

    static ConformancePackage load(Configuration config, Path upstream) throws Exception {
        byte[] pin = pin(value(config, "PIN_VALID"));
        byte[] puk = pin(value(config, "PUK_VALID"));
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
            managementKey(config), objects, keys);
    }

    private static ConformancePackage.ManagementKeyMaterial managementKey(Configuration config) {
        if (!value(config, "KEY_ALGORITHMS_CARD_MANAGEMENT").equals("08"))
            throw new IllegalArgumentException("This profile requires AES-128 management");
        byte[] key = HexFormat.of().parseHex(value(config, "keytypealgorithmkeys:KEY_9B_08"));
        if (key.length != 16) throw new IllegalArgumentException("Invalid AES-128 test key");
        return new ConformancePackage.ManagementKeyMaterial((byte) 8, key);
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
