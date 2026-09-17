using MicroCard.Framework;

[assembly: PersistentInt32(1)]
[assembly: PersistentInt32(2)]
[assembly: PersistentBytes(3, 1)]

namespace MicroCard.Samples.TransactionRecords;

[Assembly("F04D430020")]
public static class Records
{
    [Process]
    public static void Process()
    {
        int length = CommandApdu.Length;
        if (length < 1)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }

        byte[] command = new byte[length];
        CommandApdu.CopyTo(command, 0, 0, length);
        DomainStorage store = SecurityDomain.Current.Store;
        switch (command[0])
        {
            case 0:
                store.BeginTransaction();
                break;
            case 1:
                if (length != 2) { ResponseApdu.SetStatus(0x6700); return; }
                store.SetInt32(1, command[1]);
                break;
            case 2:
                if (length != 2) { ResponseApdu.SetStatus(0x6700); return; }
                store.SetInt32(2, command[1]);
                break;
            case 3:
                if (length != 2) { ResponseApdu.SetStatus(0x6700); return; }
                store.SetBytes(3, [command[1]]);
                break;
            case 4:
                store.CommitTransaction();
                break;
            case 5:
                store.AbortTransaction();
                break;
            case 6:
                byte[] response =
                [
                    (byte)store.GetInt32(1),
                    (byte)store.GetInt32(2),
                    store.ContainsBytes(3) ? store.GetBytes(3)[0] : (byte)0
                ];
                ResponseApdu.Write(response, 0, response.Length);
                break;
            case 7:
                store.BeginTransaction();
                store.CommitTransaction();
                break;
            default:
                ResponseApdu.SetStatus(0x6D00);
                break;
        }
    }
}

[Assembly("F04D430021")]
public static class LifecycleTransaction
{
    [Install]
    public static void Install() => SecurityDomain.Current.Store.BeginTransaction();

    [Process]
    public static void Process() { }
}
