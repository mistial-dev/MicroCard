using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Cryptography;

public static class SHA256
{
    public static byte[] HashData(byte[] data) => AssemblyContext.Current.Runtime.Sha256(data);

    public static int HashData(byte[] source, int sourceOffset, int sourceLength,
        byte[] destination, int destinationOffset) =>
        AssemblyContext.Current.Runtime.Sha256Into(source, sourceOffset, sourceLength, destination,
            destinationOffset);
}

public static class KeyFactory
{
    public static KeyHandle GenerateHmacSha256(KeySlot slot) =>
        AssemblyContext.Current.Keys.Generate(slot, KeyAlgorithm.HmacSha256);

    public static KeyHandle GenerateAes128(KeySlot slot) =>
        AssemblyContext.Current.Keys.Generate(slot, KeyAlgorithm.Aes128);

    public static KeyHandle GenerateP256(KeySlot slot) =>
        AssemblyContext.Current.Keys.Generate(slot, KeyAlgorithm.P256);

    public static KeyHandle Open(KeySlot slot) => AssemblyContext.Current.Keys.Open(slot);

    public static void Delete(KeySlot slot) => AssemblyContext.Current.Keys.Delete(slot);
}

public static class HmacSha256
{
    public static byte[] HashData(KeyHandle key, byte[] data) => key.HmacSha256(data);
}

public static class AesCmac
{
    public static byte[] Compute(KeyHandle key, byte[] data) => key.AesCmac(data);
}

public static class AesCbc
{
    public static byte[] Encrypt(KeyHandle key, byte[] iv, byte[] plaintext) =>
        key.EncryptCbc(iv, plaintext);

    public static byte[] Decrypt(KeyHandle key, byte[] iv, byte[] ciphertext) =>
        key.DecryptCbc(iv, ciphertext);
}

public static class AesCcm
{
    public static byte[] Encrypt(KeyHandle key, byte[] nonce, byte[] associatedData,
        byte[] plaintext) => key.EncryptCcm(nonce, associatedData, plaintext);

    public static byte[] Decrypt(KeyHandle key, byte[] nonce, byte[] associatedData,
        byte[] ciphertextAndTag) => key.DecryptCcm(nonce, associatedData, ciphertextAndTag);
}

public static class P256
{
    public static byte[] ExportPublicKey(KeyHandle key) => key.ExportP256PublicKey();

    public static byte[] SignData(KeyHandle key, byte[] data) =>
        key.SignP256(data, 0, data.Length);

    public static byte[] SignData(KeyHandle key, byte[] data, int offset, int length) =>
        key.SignP256(data, offset, length);

    public static bool VerifyData(byte[] signature, byte[] data, byte[] publicKey) =>
        AssemblyContext.Current.Runtime.VerifyP256(publicKey, data, signature);

    public static byte[] DeriveKeyMaterial(KeyHandle key, byte[] peerPublicKey) =>
        key.DeriveP256(peerPublicKey);
}

public static class RandomNumberGenerator
{
    public static void Fill(byte[] destination, int offset, int length) =>
        AssemblyContext.Current.Random.Fill(destination, offset, length);

    public static byte[] GetBytes(int length) => AssemblyContext.Current.Random.GetBytes(length);
}

public static class CryptographicOperations
{
    public static bool FixedTimeEquals(byte[] left, byte[] right) =>
        AssemblyContext.Current.Runtime.FixedTimeEquals(left, 0, left.Length, right, 0, right.Length);

    public static bool FixedTimeEquals(byte[] left, int leftOffset, int leftLength,
        byte[] right, int rightOffset, int rightLength) =>
        AssemblyContext.Current.Runtime.FixedTimeEquals(left, leftOffset, leftLength, right, rightOffset,
            rightLength);
}
