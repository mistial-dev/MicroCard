using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Cryptography;

public static class SHA256
{
    public static byte[] HashData(byte[] data) => Framework.Cryptography.Sha256(data);

    public static int HashData(byte[] source, int sourceOffset, int sourceLength,
        byte[] destination, int destinationOffset) =>
        Framework.Cryptography.Sha256Into(source, sourceOffset, sourceLength, destination,
            destinationOffset);
}

public static class KeyFactory
{
    public static KeyHandle GenerateHmacSha256(int slot) =>
        SecurityDomain.Current.Keys.Generate(slot, KeyAlgorithms.HmacSha256);

    public static KeyHandle GenerateAes128(int slot) =>
        SecurityDomain.Current.Keys.Generate(slot, KeyAlgorithms.Aes128);

    public static KeyHandle GenerateP256(int slot) =>
        SecurityDomain.Current.Keys.Generate(slot, KeyAlgorithms.P256);

    public static KeyHandle Open(int slot) => SecurityDomain.Current.Keys.Open(slot);

    public static void Delete(int slot) => SecurityDomain.Current.Keys.Delete(slot);
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
        Framework.Cryptography.VerifyP256(publicKey, data, signature);

    public static byte[] DeriveKeyMaterial(KeyHandle key, byte[] peerPublicKey) =>
        key.DeriveP256(peerPublicKey);
}

public static class RandomNumberGenerator
{
    public static void Fill(byte[] destination, int offset, int length) =>
        Framework.Cryptography.FillRandom(destination, offset, length);

    public static byte[] GetBytes(int length) => Framework.Cryptography.RandomBytes(length);
}

public static class CryptographicOperations
{
    public static bool FixedTimeEquals(byte[] left, byte[] right) =>
        Framework.Cryptography.FixedTimeEquals(left, 0, left.Length, right, 0, right.Length);

    public static bool FixedTimeEquals(byte[] left, int leftOffset, int leftLength,
        byte[] right, int rightOffset, int rightLength) =>
        Framework.Cryptography.FixedTimeEquals(left, leftOffset, leftLength, right, rightOffset,
            rightLength);
}
