using System.Buffers.Binary;
using System.Security.Cryptography;

namespace MicroCard.Build;

/// <summary>MP05 authentication only; manifest and engine validation remain separate.</summary>
internal static class PackageEnvelope
{
    static ReadOnlySpan<byte> Prefix => "MP05MicroCard signed package v5\0"u8;
    public static int HeaderBytes => Prefix.Length + 8;
    public static int OverheadBytes => HeaderBytes + 32 + 65 + 64;

    public static byte[] Create(byte[] manifest, byte[] image, byte[] seed)
    {
        if ((long)OverheadBytes + manifest.Length + image.Length > 16384) throw new InvalidDataException("Package exceeds quota");
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output);
        writer.Write(Prefix); writer.Write((uint)manifest.Length); writer.Write((uint)image.Length);
        writer.Write(manifest); writer.Write(SHA256.HashData(image)); writer.Write(PackageSignatures.PublicKey(seed));
        writer.Write(PackageSignatures.Sign(seed, output.ToArray())); writer.Write(image);
        return output.ToArray();
    }

    public static (byte[] Manifest, byte[] Image, byte[] Key) Verify(byte[] raw)
    {
        if (raw.Length < OverheadBytes || raw.Length > 16384 || !raw.AsSpan(0, Prefix.Length).SequenceEqual(Prefix))
            throw new InvalidDataException("Invalid MP05 envelope");
        int manifestLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(Prefix.Length, 4)));
        int imageLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(Prefix.Length + 4, 4)));
        if ((long)OverheadBytes + manifestLength + imageLength != raw.Length) throw new InvalidDataException("Invalid package length");
        int digestStart = HeaderBytes + manifestLength;
        int keyStart = digestStart + 32, signatureStart = keyStart + 65, imageStart = signatureStart + 64;
        byte[] key = raw[keyStart..signatureStart];
        if (!PackageSignatures.Verify(key, raw[..signatureStart], raw[signatureStart..imageStart]))
            throw new InvalidDataException("Invalid signature");
        byte[] image = raw[imageStart..];
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(image), raw.AsSpan(digestStart, 32)))
            throw new InvalidDataException("Image digest mismatch");
        return (raw[HeaderBytes..digestStart], image, key);
    }
}
