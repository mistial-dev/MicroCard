using MicroCard.Cryptography;
using MicroCard.Framework;
using MicroCard.Security;

[assembly: PersistentBytes(1, 248)]

[assembly: Dependency("MicroCard.Cryptography", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    PackageVersion = 1,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]
[assembly: Dependency("MicroCard.Security", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    PackageVersion = 1,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

namespace MicroCard.Samples.Credential;

[CardAssembly("F04D4308C0")]
public static class Credential
{
    private const int PinSlot = 1;
    private const int SigningKeySlot = 2;
    private const int PublicDataKey = 1;

    public static void Install() => KeyFactory.GenerateP256((KeySlot)SigningKeySlot);

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
            if (command.Length < 14)
            {
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
                return;
            }
            Provision(command);
            return;
        }
        if (operation == 1)
        {
            Write(AssemblyContext.Current.Storage.GetBytes((StorageId)PublicDataKey));
            return;
        }
        if (operation == 2)
        {
            Write(P256.ExportPublicKey(KeyFactory.Open((KeySlot)SigningKeySlot)));
            return;
        }
        if (operation == 3)
        {
            Sign(command);
            return;
        }
        if (operation == 4)
        {
            byte[] response = [(byte)Pin.RetriesRemaining((CredentialSlot)PinSlot)];
            Write(response);
            return;
        }
        if (operation == 5)
        {
            if (command.Length != 13)
            {
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
                return;
            }
            byte[] response = [Pin.Unblock((CredentialSlot)PinSlot, command, 1, 8, command, 9, 4)
                ? (byte)1 : (byte)0];
            Write(response);
            return;
        }
        AssemblyContext.Current.Response.SetStatus((StatusWord)0x6D00);
    }

    private static void Provision(byte[] command)
    {
        Pin.Create((CredentialSlot)PinSlot, command, 1, 4, 3, command, 5, 8, 3);
        AssemblyContext.Current.Storage.SetBytes((StorageId)PublicDataKey, command, 13, command.Length - 13);
    }

    private static void Sign(byte[] command)
    {
        if (command.Length < 6)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
            return;
        }
        if (!Pin.Verify((CredentialSlot)PinSlot, command, 1, 4))
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6982);
            return;
        }
        Write(P256.SignData(KeyFactory.Open((KeySlot)SigningKeySlot), command, 5, command.Length - 5));
    }

    private static void Write(byte[] data) => AssemblyContext.Current.Response.Write(data, 0, data.Length);
}
