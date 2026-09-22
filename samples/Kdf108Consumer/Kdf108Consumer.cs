using MicroCard.Cryptography;
using MicroCard.Framework;

[assembly: Dependency("Kdf108", "=0.1.0", Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

[CardAssembly("F04D430108")]
public static class Kdf108Consumer
{
    public static void Install() => AssemblyContext.Current.Keys.Generate((KeySlot)2, KeyAlgorithm.Aes128);

    public static void Uninstall() => AssemblyContext.Current.Keys.Delete((KeySlot)2);

    public static void Process()
    {
        int inputLength = AssemblyContext.Current.Command.Length;
        if (inputLength < 2)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
            return;
        }
        var input = new byte[inputLength];
        AssemblyContext.Current.Command.CopyTo(input, 0, 0, input.Length);
        int keyPurpose = input[0];
        int contextLength = input[1];
        if (contextLength > 239 || contextLength != inputLength - 2)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
            return;
        }
        var context = new byte[contextLength];
        for (int index = 0; index < contextLength; index++)
            context[index] = input[index + 2];
        var derived = Kdf108.DeriveScp03(AssemblyContext.Current.Keys.Open((KeySlot)2), keyPurpose, context, 16);
        if (derived.Length != 16)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6A80);
            return;
        }
        AssemblyContext.Current.Response.Write(derived, 0, derived.Length);
    }
}
