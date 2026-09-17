using MicroCard.Cryptography;
using MicroCard.Framework;
using MicroCard.Security;

[assembly: PersistentBytes(1, 248)]

[assembly: Dependency("MicroCard.Cryptography", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    PackageVersion = 1,
    SignerPublicKeyHex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")]
[assembly: Dependency("MicroCard.Security", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    PackageVersion = 1,
    SignerPublicKeyHex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")]

namespace MicroCard.Samples.Credential;

[Assembly("F04D4308C0")]
public static class Credential
{
    private const int PinSlot = 1;
    private const int SigningKeySlot = 2;
    private const int PublicDataKey = 1;

    [Install]
    public static void Install() => KeyFactory.GenerateP256(SigningKeySlot);

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
            Provision(command);
            return;
        }
        if (operation == 1)
        {
            Write(SecurityDomain.Current.Store.GetBytes(PublicDataKey));
            return;
        }
        if (operation == 2)
        {
            Write(P256.ExportPublicKey(KeyFactory.Open(SigningKeySlot)));
            return;
        }
        if (operation == 3)
        {
            Sign(command);
            return;
        }
        if (operation == 4)
        {
            byte[] response = [(byte)Pin.RetriesRemaining(PinSlot)];
            Write(response);
            return;
        }
        if (operation == 5)
        {
            if (command.Length != 13)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            byte[] response = [Pin.Unblock(PinSlot, command, 1, 8, command, 9, 4)
                ? (byte)1 : (byte)0];
            Write(response);
            return;
        }
        ResponseApdu.SetStatus(0x6D00);
    }

    [Transaction]
    private static void Provision(byte[] command)
    {
        if (command.Length < 14)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        Pin.Create(PinSlot, command, 1, 4, 3, command, 5, 8, 3);
        SecurityDomain.Current.Store.SetBytes(PublicDataKey, command, 13, command.Length - 13);
    }

    private static void Sign(byte[] command)
    {
        if (command.Length < 6)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        if (!Pin.Verify(PinSlot, command, 1, 4))
        {
            ResponseApdu.SetStatus(0x6982);
            return;
        }
        Write(P256.SignData(KeyFactory.Open(SigningKeySlot), command, 5, command.Length - 5));
    }

    private static void Write(byte[] data) => ResponseApdu.Write(data, 0, data.Length);
}
