using MicroCard.Framework;
using System.Transactions;

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
        _ = Transaction.Current;
        int length = CommandApdu.Length;
        if (length < 1)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }

        byte[] command = new byte[length];
        CommandApdu.CopyTo(command, 0, 0, length);
        switch (command[0])
        {
            case 0:
                if (length != 4) { ResponseApdu.SetStatus(0x6700); return; }
                CommitUpdate(command);
                break;
            case 1:
                if (length != 4) { ResponseApdu.SetStatus(0x6700); return; }
                AbortUpdate(command);
                break;
            case 2:
                DomainStorage store = SecurityDomain.Current.Store;
                byte[] response =
                [
                    (byte)store.GetInt32(1),
                    (byte)store.GetInt32(2),
                    store.ContainsBytes(3) ? store.GetBytes(3)[0] : (byte)0
                ];
                ResponseApdu.Write(response, 0, response.Length);
                break;
            default:
                ResponseApdu.SetStatus(0x6D00);
                break;
        }
    }

    private static void CommitUpdate(byte[] command)
    {
        using var scope = new TransactionScope();
        _ = Transaction.Current!.TransactionInformation.Status;
        Write(command);
        scope.Complete();
    }

    private static void AbortUpdate(byte[] command)
    {
        using var scope = new TransactionScope();
        _ = Transaction.Current!.TransactionInformation.Status;
        Write(command);
    }

    private static void Write(byte[] command)
    {
        DomainStorage store = SecurityDomain.Current.Store;
        store.SetInt32(1, command[1]);
        store.SetInt32(2, command[2]);
        store.SetBytes(3, [command[3]]);
    }
}
