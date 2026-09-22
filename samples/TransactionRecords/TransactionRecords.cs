using MicroCard.Framework;
using System.Transactions;

[assembly: PersistentInt32(1)]
[assembly: PersistentInt32(2)]
[assembly: PersistentBytes(3, 1)]

namespace MicroCard.Samples.TransactionRecords;

[CardAssembly("F04D430020")]
public static class Records
{
    public static void Process()
    {
        _ = Transaction.Current;
        int length = AssemblyContext.Current.Command.Length;
        if (length < 1)
        {
            AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);
            return;
        }

        byte[] command = new byte[length];
        AssemblyContext.Current.Command.CopyTo(command, 0, 0, length);
        switch (command[0])
        {
            case 0:
                if (length != 4) { AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700); return; }
                CommitUpdate(command);
                break;
            case 1:
                if (length != 4) { AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700); return; }
                AbortUpdate(command);
                break;
            case 2:
                StorageService store = AssemblyContext.Current.Storage;
                byte[] response =
                [
                    (byte)store.GetInt32((StorageId)1),
                    (byte)store.GetInt32((StorageId)2),
                    store.ContainsBytes((StorageId)3) ? store.GetBytes((StorageId)3)[0] : (byte)0
                ];
                AssemblyContext.Current.Response.Write(response, 0, response.Length);
                break;
            default:
                AssemblyContext.Current.Response.SetStatus((StatusWord)0x6D00);
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
        StorageService store = AssemblyContext.Current.Storage;
        store.SetInt32((StorageId)1, command[1]);
        store.SetInt32((StorageId)2, command[2]);
        store.SetBytes((StorageId)3, [command[3]]);
    }
}
