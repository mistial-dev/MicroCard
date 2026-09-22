using MicroCard.Cryptography;
using MicroCard.Framework;

[assembly: Dependency("MicroCard.Cryptography", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

namespace MicroCard.Samples.CryptographyConsumer;

[CardAssembly("F04D4306C0")]
public static class CryptographyConsumer
{
    private const int HmacSlot = 5;
    private const int AesSlot = 6;
    private const int P256Slot = 7;

    public static void Install()
    {
        KeyFactory.GenerateHmacSha256((KeySlot)HmacSlot);
        KeyFactory.GenerateAes128((KeySlot)AesSlot);
        KeyFactory.GenerateP256((KeySlot)P256Slot);
    }

    public static void Uninstall()
    {
        KeyFactory.Delete((KeySlot)HmacSlot);
        KeyFactory.Delete((KeySlot)AesSlot);
        KeyFactory.Delete((KeySlot)P256Slot);
    }

    public static void Process()
    {
        int length = AssemblyContext.Current.Command.Length;
        if (length < 1)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
            return;
        }
        var command = new byte[length];
        AssemblyContext.Current.Command.CopyTo(command, 0, 0, length);
        int operation = command[0];
        if (operation == 0)
        {
            var digest = new byte[40];
            SHA256.HashData(command, 1, length - 1, digest, 4);
            AssemblyContext.Current.Response.Write(digest, 4, 32);
            return;
        }
        if (operation == 12)
        {
            SHA256.HashData(command, 1, length - 1, new byte[31], 0);
            return;
        }
        if (operation == 13)
        {
            SHA256.HashData(command, 1, length, new byte[32], 0);
            return;
        }
        if (operation == 14)
        {
            SHA256.HashData(command, 1, length - 1, command, 0);
            AssemblyContext.Current.Response.Write(command, 0, 32);
            return;
        }
        if (operation == 15)
        {
            AssemblyContext.Current.Response.Write(System.Security.Cryptography.SHA256.HashData(
                Copy(command, 1, length - 1)), 0, 32);
            return;
        }
        if (operation == 16)
        {
            Write(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            return;
        }
        if (operation == 17)
        {
            Write(System.Security.Cryptography.RandomNumberGenerator.GetBytes(1025));
            return;
        }
        if (operation == 18)
        {
            if (length != 65)
            {
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
                return;
            }
            byte[] result = [CryptographicOperations.FixedTimeEquals(command, 1, 32,
                command, 33, 32) ? (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 19)
        {
            CryptographicOperations.FixedTimeEquals(command, 1, length, command, 0, length);
            return;
        }
        var data = Copy(command, 1, length - 1);
        if (operation == 1)
        {
            if (data.Length < 129)
            {
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
                return;
            }
            var publicKey = Copy(data, 0, 65);
            var signature = Copy(data, 65, 64);
            var message = Copy(data, 129, data.Length - 129);
            byte[] result = [P256.VerifyData(signature, message, publicKey) ? (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 2)
        {
            Write(HmacSha256.HashData(KeyFactory.Open((KeySlot)HmacSlot), data));
            return;
        }
        if (operation == 3)
        {
            Write(AesCmac.Compute(KeyFactory.Open((KeySlot)AesSlot), data));
            return;
        }
        if (operation == 4)
        {
            var iv = new byte[16];
            var key = KeyFactory.Open((KeySlot)AesSlot);
            Write(AesCbc.Decrypt(key, iv, AesCbc.Encrypt(key, iv, data)));
            return;
        }
        if (operation == 5)
        {
            var nonce = new byte[13];
            var associatedData = new byte[0];
            var key = KeyFactory.Open((KeySlot)AesSlot);
            Write(AesCcm.Decrypt(key, nonce, associatedData,
                AesCcm.Encrypt(key, nonce, associatedData, data)));
            return;
        }
        if (operation == 6)
        {
            byte[] result = [P256.VerifyData(new byte[63], new byte[0], new byte[64]) ?
                (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 7)
        {
            Write(P256.ExportPublicKey(KeyFactory.Open((KeySlot)P256Slot)));
            return;
        }
        if (operation == 8)
        {
            Write(P256.SignData(KeyFactory.Open((KeySlot)P256Slot), data));
            return;
        }
        if (operation == 9)
        {
            if (data.Length < 129)
            {
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
                return;
            }
            var publicKey = Copy(data, 0, 65);
            var signature = Copy(data, 65, 64);
            var message = Copy(data, 129, data.Length - 129);
            byte[] result = [P256.VerifyData(signature, message, publicKey) ? (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 10)
        {
            Write(P256.DeriveKeyMaterial(KeyFactory.Open((KeySlot)P256Slot), data));
            return;
        }
        if (operation == 11)
        {
            var random = new byte[32];
            RandomNumberGenerator.Fill(random, 0, random.Length);
            Write(random);
            return;
        }
        AssemblyContext.Current.Response.SetStatus((StatusWord)0x6D00);
    }

    private static byte[] Copy(byte[] source, int offset, int length)
    {
        var result = new byte[length];
        for (int index = 0; index < length; index++)
            result[index] = source[offset + index];
        return result;
    }

    private static void Write(byte[] data) => AssemblyContext.Current.Response.Write(data, 0, data.Length);
}
