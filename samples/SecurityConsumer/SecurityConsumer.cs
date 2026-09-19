using MicroCard.Framework;
using MicroCard.Security;

[assembly: Dependency("MicroCard.Security", "=0.1.0",
    Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

[assembly: PersistentInt32(1)]

namespace MicroCard.Samples.SecurityConsumer;

[Assembly("F04D4307C0")]
public static class SecurityConsumer
{
    private const int Slot = 1;

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
        var data = Copy(command, 1, length - 1);
        if (operation == 0)
        {
            if (data.Length != 12)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            Pin.Create(Slot, Copy(data, 0, 4), 3, Copy(data, 4, 8), 2);
            return;
        }
        if (operation == 1)
        {
            Write(Pin.Verify(Slot, data) ? 1 : 0);
            return;
        }
        if (operation == 2)
        {
            Write(Pin.RetriesRemaining(Slot));
            return;
        }
        if (operation == 3)
        {
            Pin.Verify(Slot, data);
            SecurityDomain.Current.Keys.Open(99);
            return;
        }
        if (operation == 4)
        {
            if (data.Length != 12)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            Write(Pin.Unblock(Slot, Copy(data, 0, 8), Copy(data, 8, 4)) ? 1 : 0);
            return;
        }
        if (operation == 5)
        {
            Write(Pin.PukRetriesRemaining(Slot));
            return;
        }
        if (operation == 6)
        {
            if (data.Length != 8 || !Pin.Verify(Slot, Copy(data, 0, 4)))
            {
                Write(0);
                return;
            }
            Pin.Change(Slot, Copy(data, 4, 4));
            Write(Pin.IsVerified(Slot) ? 1 : 0);
            return;
        }
        if (operation == 7)
        {
            Write(Pin.IsVerified(Slot) ? 1 : 0);
            return;
        }
        if (operation == 8)
        {
            if (data.Length != 12)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            Pin.Unblock(Slot, Copy(data, 0, 8), Copy(data, 8, 4));
            SecurityDomain.Current.Keys.Open(99);
            return;
        }
        if (operation == 9 && data.Length == 1)
        {
            SecurityDomain.Current.Store.SetInt32(1, data[0]);
            return;
        }
        if (operation == 10)
        {
            Write(SecurityDomain.Current.Store.GetInt32(1));
            return;
        }
        ResponseApdu.SetStatus(0x6D00);
    }

    [Select] public static void Select() => Lifecycle(1);
    [Deselect] public static void Deselect() => Lifecycle(2);
    [Install] public static void Install() => Lifecycle(3);
    [Uninstall] public static void Uninstall() => Lifecycle(4);

    private static void Lifecycle(int phase)
    {
        var store = SecurityDomain.Current.Store;
        if (store.GetInt32(1) != phase || Pin.RetriesRemaining(Slot) == 0)
            return;
        // Acceptance checks that this write rolls back while the failed PIN persists.
        store.SetInt32(1, 0);
        Pin.Verify(Slot, new byte[4]);
        SecurityDomain.Current.Keys.Open(99);
    }

    private static byte[] Copy(byte[] source, int offset, int length)
    {
        var result = new byte[length];
        for (int index = 0; index < length; index++)
            result[index] = source[offset + index];
        return result;
    }

    private static void Write(int value)
    {
        byte[] response = [(byte)value];
        ResponseApdu.Write(response, 0, 1);
    }
}
