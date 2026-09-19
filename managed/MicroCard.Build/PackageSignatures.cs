using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Signers;

namespace MicroCard.Build;

internal static class PackageSignatures
{
    static Org.BouncyCastle.Asn1.X9.X9ECParameters Curve() => SecNamedCurves.GetByName("secp256r1");

    static BigInteger Scalar(byte[] seed)
    {
        if (seed.Length != 32) throw new InvalidDataException("P-256 seed must be 32 bytes");
        var d = new BigInteger(1, seed);
        if (d.SignValue <= 0 || d.CompareTo(Curve().N) >= 0) throw new InvalidDataException("Seed is not a P-256 private scalar");
        return d;
    }

    public static byte[] PublicKey(byte[] seed) => Curve().G.Multiply(Scalar(seed)).Normalize().GetEncoded(false);

    // Deterministic ECDSA over SHA-256, in the low form a card accepts.
    public static byte[] Sign(byte[] seed, byte[] message)
    {
        var curve = Curve();
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(Scalar(seed), new ECDomainParameters(curve.Curve, curve.G, curve.N)));
        var parts = signer.GenerateSignature(SHA256.HashData(message));
        var r = parts[0];
        var s = parts[1];
        if (s.CompareTo(curve.N.ShiftRight(1)) > 0) s = curve.N.Subtract(s);
        var output = new byte[64];
        Width32(r).CopyTo(output, 0);
        Width32(s).CopyTo(output, 32);
        return output;
    }

    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (publicKey.Length != 65 || publicKey[0] != 0x04 || signature.Length != 64) return false;
        var curve = Curve();
        var r = new BigInteger(1, signature[..32]);
        var s = new BigInteger(1, signature[32..]);
        // A card takes only the low form, so the packager has to have produced it.
        if (s.CompareTo(curve.N.ShiftRight(1)) > 0) return false;
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters(curve.Curve.DecodePoint(publicKey), new ECDomainParameters(curve.Curve, curve.G, curve.N)));
        return verifier.VerifySignature(SHA256.HashData(message), r, s);
    }

    static byte[] Width32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length > 32) throw new InvalidDataException("ECDSA component exceeds 32 bytes");
        var padded = new byte[32];
        bytes.CopyTo(padded, 32 - bytes.Length);
        return padded;
    }
}
