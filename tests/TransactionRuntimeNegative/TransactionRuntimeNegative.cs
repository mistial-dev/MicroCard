using MicroCard.Framework;

[assembly: PersistentInt32(1)]

namespace MicroCard.Tests.TransactionRuntimeNegative;

[Assembly("F04D430022")]
public static class InvalidTransactionSequences
{
    [Process]
    public static void Process()
    {
        byte[] command = new byte[CommandApdu.Length];
        CommandApdu.CopyTo(command, 0, 0, command.Length);
        DomainStorage store = SecurityDomain.Current.Store;
        switch (command[0])
        {
            case 0:
                store.BeginTransaction();
                Hardware.Write(1, 1);
                break;
            case 1:
                store.BeginTransaction();
                store.CommitTransaction();
                store.SetInt32(1, 88);
                break;
            case 2:
                store.BeginTransaction();
                store.AbortTransaction();
                store.GetInt32(1);
                break;
        }
    }
}
