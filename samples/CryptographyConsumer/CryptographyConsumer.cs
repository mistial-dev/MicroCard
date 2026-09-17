using MicroCard.Cryptography;
using MicroCard.Framework;

[assembly: Dependency("MicroCard.Cryptography", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")]

namespace MicroCard.Samples.CryptographyConsumer;

[Assembly("F04D4306C0")]
public static class CryptographyConsumer
{
    private const int HmacSlot = 5;
    private const int AesSlot = 6;
    private const int P256Slot = 7;

    [Install]
    public static void Install()
    {
        KeyFactory.GenerateHmacSha256(HmacSlot);
        KeyFactory.GenerateAes128(AesSlot);
        KeyFactory.GenerateP256(P256Slot);
    }

    [Uninstall]
    public static void Uninstall()
    {
        KeyFactory.Delete(HmacSlot);
        KeyFactory.Delete(AesSlot);
        KeyFactory.Delete(P256Slot);
    }

    [Process]
    public static void Process()
    {
        int length = CommandApdu.Length;
        if (length < 1)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        var command = new byte[length];
        CommandApdu.CopyTo(command, 0, 0, length);
        int operation = command[0];
        if (operation == 0)
        {
            var digest = new byte[40];
            SHA256.HashData(command, 1, length - 1, digest, 4);
            ResponseApdu.Write(digest, 4, 32);
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
            ResponseApdu.Write(command, 0, 32);
            return;
        }
        if (operation == 15)
        {
            ResponseApdu.Write(System.Security.Cryptography.SHA256.HashData(
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
                ResponseApdu.SetStatus(0x6700);
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
            if (data.Length < 96)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            var publicKey = Copy(data, 0, 32);
            var signature = Copy(data, 32, 64);
            var message = Copy(data, 96, data.Length - 96);
            byte[] result = [Ed25519.Verify(signature, message, publicKey) ? (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 2)
        {
            Write(HmacSha256.HashData(KeyFactory.Open(HmacSlot), data));
            return;
        }
        if (operation == 3)
        {
            Write(AesCmac.Compute(KeyFactory.Open(AesSlot), data));
            return;
        }
        if (operation == 4)
        {
            var iv = new byte[16];
            var key = KeyFactory.Open(AesSlot);
            Write(AesCbc.Decrypt(key, iv, AesCbc.Encrypt(key, iv, data)));
            return;
        }
        if (operation == 5)
        {
            var nonce = new byte[13];
            var associatedData = new byte[0];
            var key = KeyFactory.Open(AesSlot);
            Write(AesCcm.Decrypt(key, nonce, associatedData,
                AesCcm.Encrypt(key, nonce, associatedData, data)));
            return;
        }
        if (operation == 6)
        {
            byte[] result = [Ed25519.Verify(new byte[63], new byte[0], new byte[31]) ?
                (byte)1 : (byte)0];
            Write(result);
            return;
        }
        if (operation == 7)
        {
            Write(P256.ExportPublicKey(KeyFactory.Open(P256Slot)));
            return;
        }
        if (operation == 8)
        {
            Write(P256.SignData(KeyFactory.Open(P256Slot), data));
            return;
        }
        if (operation == 9)
        {
            if (data.Length < 129)
            {
                ResponseApdu.SetStatus(0x6700);
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
            Write(P256.DeriveKeyMaterial(KeyFactory.Open(P256Slot), data));
            return;
        }
        if (operation == 11)
        {
            var random = new byte[32];
            RandomNumberGenerator.Fill(random, 0, random.Length);
            Write(random);
            return;
        }
        ResponseApdu.SetStatus(0x6D00);
    }

    private static byte[] Copy(byte[] source, int offset, int length)
    {
        var result = new byte[length];
        for (int index = 0; index < length; index++)
            result[index] = source[offset + index];
        return result;
    }

    private static void Write(byte[] data) => ResponseApdu.Write(data, 0, data.Length);
}
