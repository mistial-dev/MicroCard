using MicroCard.Framework;
using System.Transactions;

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
        using var scope = new TransactionScope();
        if (command[0] == 0) Hardware.Write(1, 1);
        SecurityDomain.Current.Store.SetInt32(1, 88);
        scope.Complete();
    }
}
