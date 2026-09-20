package dev.mistial.tools.openfips201.nist;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.cert.jcajce.JcaCertStore;

/** Refreshes the signed expiration in the generated, test-only CHUID fixture. */
public final class MicroCardNistChuid {
  private static final ASN1ObjectIdentifier CHUID_CONTENT_TYPE =
      new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1");

  private MicroCardNistChuid() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 11 || args[4].length() != 8) {
      throw new IllegalArgumentException(
          "usage: CHUID_IN CHUID_OUT KEY CERT DATE SECURITY_IN SECURITY_OUT FP_IN FP_OUT FACE_IN FACE_OUT");
    }
    Security.addProvider(new BouncyCastleProvider());
    byte[] old = Files.readAllBytes(Path.of(args[0]));
    ByteArrayOutputStream signed = new ByteArrayOutputStream();
    int offset = 0;
    while (offset < old.length) {
      int tag = old[offset] & 0xff;
      int header = headerLength(old, offset);
      int length = valueLength(old, offset);
      int end = offset + header + length;
      if (end > old.length) throw new IllegalArgumentException("truncated CHUID element");
      if (tag == 0x35) {
        signed.write(tlv(0x35, args[4].getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
      } else if (tag != 0x3e && tag != 0xfe) {
        signed.write(old, offset, end - offset);
      }
      offset = end;
    }
    signed.write(tlv(0xfe, new byte[0]));
    byte[] content = signed.toByteArray();
    PrivateKey key = readKey(Path.of(args[2]));
    X509Certificate certificate = readCertificate(Path.of(args[3]));
    byte[] cms = sign(content, key, certificate, CHUID_CONTENT_TYPE, false, true, null);
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    result.write(content, 0, content.length - 2);
    result.write(tlv(0x3e, cms));
    result.write(tlv(0xfe, new byte[0]));
    byte[] refreshedChuid = result.toByteArray();
    Files.write(Path.of(args[1]), refreshedChuid);
    byte[] oldFingerprint = Files.readAllBytes(Path.of(args[7]));
    byte[] fingerprint = resignBiometric(oldFingerprint, key, certificate);
    Files.write(Path.of(args[8]), fingerprint);
    byte[] oldFace = Files.readAllBytes(Path.of(args[9]));
    byte[] face = resignBiometric(oldFace, key, certificate);
    Files.write(Path.of(args[10]), face);
    resignSecurityObject(Path.of(args[5]), Path.of(args[6]), key, certificate, refreshedChuid,
        oldFingerprint, fingerprint, oldFace, face);
  }

  private static PrivateKey readKey(Path keyPath) throws Exception {
    try (PEMParser parser = new PEMParser(Files.newBufferedReader(keyPath))) {
      Object value = parser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      return value instanceof PEMKeyPair
          ? converter.getKeyPair((PEMKeyPair) value).getPrivate()
          : converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) value);
    }
  }

  private static X509Certificate readCertificate(Path certificatePath) throws Exception {
    try (PemReader reader = new PemReader(Files.newBufferedReader(certificatePath))) {
      return (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new java.io.ByteArrayInputStream(reader.readPemObject().getContent()));
    }
  }

  private static byte[] sign(
      byte[] content,
      PrivateKey key,
      X509Certificate certificate,
      ASN1ObjectIdentifier contentType,
      boolean encapsulate,
      boolean includeCertificate,
      AttributeTable carriedAttributes) throws Exception {
    String signatureAlgorithm = "RSA".equals(key.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
    ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(key);
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    @SuppressWarnings("unchecked")
    Hashtable<ASN1ObjectIdentifier, Attribute> attributes =
        carriedAttributes == null
            ? new Hashtable<ASN1ObjectIdentifier, Attribute>()
            : carriedAttributes.toHashtable();
    attributes.remove(CMSAttributes.contentType);
    attributes.remove(CMSAttributes.messageDigest);
    attributes.remove(CMSAttributes.signingTime);
    ASN1ObjectIdentifier signerDn = new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
    attributes.put(signerDn, new Attribute(signerDn,
        new DERSet(X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()))));
    generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
        .setSignedAttributeGenerator(
            new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)))
        .build(signer, certificate));
    if (includeCertificate) {
      generator.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
    }
    CMSSignedData data = generator.generate(
        new CMSProcessableByteArray(contentType, content), encapsulate);
    return data.getEncoded();
  }

  private static void resignSecurityObject(
      Path input, Path output, PrivateKey key, X509Certificate certificate, byte[] chuid,
      byte[] oldFingerprint, byte[] fingerprint, byte[] oldFace, byte[] face)
      throws Exception {
    byte[] old = Files.readAllBytes(input);
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    int offset = 0;
    boolean replaced = false;
    while (offset < old.length) {
      int tag = old[offset] & 0xff;
      int header = headerLength(old, offset);
      int length = valueLength(old, offset);
      int end = offset + header + length;
      if (end > old.length) throw new IllegalArgumentException("truncated Security Object element");
      if (tag == 0xbb) {
        CMSSignedData prior = new CMSSignedData(java.util.Arrays.copyOfRange(old, offset + header, end));
        byte[] oldContent = (byte[]) prior.getSignedContent().getContent();
        LDSSecurityObject oldLds = LDSSecurityObject.getInstance(ASN1Primitive.fromByteArray(oldContent));
        DataGroupHash[] oldHashes = oldLds.getDatagroupHash();
        DataGroupHash[] hashes = new DataGroupHash[oldHashes.length];
        MessageDigest digest = MessageDigest.getInstance(
            oldLds.getDigestAlgorithmIdentifier().getAlgorithm().getId(), "BC");
        for (int i = 0; i < oldHashes.length; i++) {
          byte[] oldHash = oldHashes[i].getDataGroupHashValue().getOctets();
          byte[] replacement = null;
          if (java.util.Arrays.equals(oldHash, digest.digest(oldFingerprint))) replacement = fingerprint;
          if (java.util.Arrays.equals(oldHash, digest.digest(oldFace))) replacement = face;
          if (oldHashes[i].getDataGroupNumber() == 1) replacement = chuid;
          hashes[i] = replacement == null ? oldHashes[i] : new DataGroupHash(
              oldHashes[i].getDataGroupNumber(), new DEROctetString(digest.digest(replacement)));
        }
        byte[] content = new LDSSecurityObject(
            oldLds.getDigestAlgorithmIdentifier(), hashes).getEncoded("DER");
        byte[] cms = sign(content, key, certificate,
            new ASN1ObjectIdentifier(prior.getSignedContentTypeOID()), true, false, null);
        result.write(tlv(0xbb, cms));
        replaced = true;
      } else {
        result.write(old, offset, end - offset);
      }
      offset = end;
    }
    if (!replaced) throw new IllegalArgumentException("Security Object has no BB signature");
    Files.write(output, result.toByteArray());
  }

  private static byte[] resignBiometric(
      byte[] old, PrivateKey key, X509Certificate certificate) throws Exception {
    int cmsOffset = -1;
    for (int i = 4; i < old.length - 15; i++) {
      if ((old[i] & 0xff) != 0x30) continue;
      int lengthByte = old[i + 1] & 0xff;
      if (lengthByte > 0x83) continue;
      int header = headerLength(old, i);
      if (i + header + valueLength(old, i) == old.length - 2
          && old[i + header] == 0x06) {
        cmsOffset = i;
        break;
      }
    }
    if (cmsOffset < 0) throw new IllegalArgumentException("biometric object has no trailing CMS");
    CMSSignedData prior = new CMSSignedData(
        java.util.Arrays.copyOfRange(old, cmsOffset, old.length - 2));
    SignerInformation priorSigner =
        (SignerInformation) prior.getSignerInfos().getSigners().iterator().next();
    byte[] content = java.util.Arrays.copyOfRange(old, 4, cmsOffset);
    byte[] cms = sign(content, key, certificate,
        new ASN1ObjectIdentifier(prior.getSignedContentTypeOID()), false, false,
        priorSigner.getSignedAttributes());
    content[6] = (byte) (cms.length >>> 8);
    content[7] = (byte) cms.length;
    cms = sign(content, key, certificate,
        new ASN1ObjectIdentifier(prior.getSignedContentTypeOID()), false, false,
        priorSigner.getSignedAttributes());
    ByteArrayOutputStream value = new ByteArrayOutputStream();
    value.write(content);
    value.write(cms);
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    result.write(tlv(0xbc, value.toByteArray()));
    result.write(tlv(0xfe, new byte[0]));
    return result.toByteArray();
  }

  private static int headerLength(byte[] value, int offset) {
    int first = value[offset + 1] & 0xff;
    return first < 0x80 ? 2 : 2 + (first & 0x7f);
  }

  private static int valueLength(byte[] value, int offset) {
    int first = value[offset + 1] & 0xff;
    if (first < 0x80) return first;
    int count = first & 0x7f;
    if (count == 0 || count > 3) throw new IllegalArgumentException("unsupported CHUID length");
    int result = 0;
    for (int i = 0; i < count; i++) result = (result << 8) | (value[offset + 2 + i] & 0xff);
    return result;
  }

  private static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    result.write(tag);
    if (value.length < 0x80) {
      result.write(value.length);
    } else if (value.length <= 0xff) {
      result.write(0x81);
      result.write(value.length);
    } else {
      result.write(0x82);
      result.write(value.length >>> 8);
      result.write(value.length);
    }
    result.write(value, 0, value.length);
    return result.toByteArray();
  }
}
