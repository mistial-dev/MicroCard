package dev.mistial.microcard.wallet;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;

final class DemoCertificates {
    record Result(Path issuer, Path credential) { }

    static Result issue(Path directory, String label, byte[] publicKey) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair issuerKey = generator.generateKeyPair();
        PublicKey credentialKey = decode(publicKey);
        Instant now = Instant.now();
        Date start = Date.from(now.minusSeconds(60));
        Date end = Date.from(now.plusSeconds(86400L * 30));
        X500Name issuerName = new X500Name("CN=MicroCard 0.1-wip Demo Issuer");
        var issuerBuilder = new JcaX509v3CertificateBuilder(issuerName, BigInteger.ONE, start, end,
            issuerName, issuerKey.getPublic());
        issuerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        issuerBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        var issuerSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate());
        var issuerCertificate = new JcaX509CertificateConverter().getCertificate(issuerBuilder.build(issuerSigner));

        X500Name subject = new X500Name("CN=MicroCard " + label + " Demo Credential");
        X509v3CertificateBuilder credentialBuilder = new JcaX509v3CertificateBuilder(issuerName,
            new BigInteger(127, new SecureRandom()).add(BigInteger.TWO), start, end, subject, credentialKey);
        credentialBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        credentialBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        var credentialCertificate = new JcaX509CertificateConverter().getCertificate(
            credentialBuilder.build(issuerSigner));
        credentialCertificate.verify(issuerKey.getPublic());

        Files.createDirectories(directory);
        Path issuer = directory.resolve("demo-issuer.pem");
        Path credential = directory.resolve(label.toLowerCase(Locale.ROOT) + "-credential.pem");
        writePem(issuer, issuerCertificate); writePem(credential, credentialCertificate);
        return new Result(issuer, credential);
    }

    private static PublicKey decode(byte[] raw) throws Exception {
        if (raw.length != 65 || raw[0] != 4) throw new IllegalArgumentException("Invalid P-256 public key");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(raw, 1, 33)),
            new BigInteger(1, Arrays.copyOfRange(raw, 33, 65)));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }

    private static void writePem(Path path, Object value) throws IOException {
        try (var writer = new JcaPEMWriter(Files.newBufferedWriter(path))) { writer.writeObject(value); }
    }
}
