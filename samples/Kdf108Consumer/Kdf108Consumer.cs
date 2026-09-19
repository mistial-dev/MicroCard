using MicroCard.Cryptography;
using MicroCard.Framework;

[assembly: Dependency("Kdf108", "=0.1.0", Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

[Assembly("F04D430108")]
public static class Kdf108Consumer
{
    [Install]
    public static void Install() => SecurityDomain.Current.Keys.Generate(2, KeyAlgorithms.Aes128);

    [Uninstall]
    public static void Uninstall() => SecurityDomain.Current.Keys.Delete(2);

    [Process]
    public static void Process()
    {
        int inputLength = CommandApdu.Length;
        if (inputLength < 2)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        var input = new byte[inputLength];
        CommandApdu.CopyTo(input, 0, 0, input.Length);
        int keyPurpose = input[0];
        int contextLength = input[1];
        if (contextLength > 239 || contextLength != inputLength - 2)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        var context = new byte[contextLength];
        for (int index = 0; index < contextLength; index++)
            context[index] = input[index + 2];
        var derived = Kdf108.DeriveScp03(SecurityDomain.Current.Keys.Open(2), keyPurpose, context, 16);
        if (derived.Length != 16)
        {
            ResponseApdu.SetStatus(0x6A80);
            return;
        }
        ResponseApdu.Write(derived, 0, derived.Length);
    }
}
