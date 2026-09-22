using MicroCard.Framework;
using System.Transactions;

[assembly: PersistentInt32(1)]

namespace MicroCard.Tests.TransactionRuntimeNegative;

[CardAssembly("F04D430022")]
public static class InvalidTransactionSequences
{
    public static void Process()
    {
        byte[] command = new byte[AssemblyContext.Current.Command.Length];
        AssemblyContext.Current.Command.CopyTo(command, 0, 0, command.Length);
        using var scope = new TransactionScope();
        if (command[0] == 0) AssemblyContext.Current.Runtime.WriteHardware(1, 1);
        AssemblyContext.Current.Storage.SetInt32((StorageId)1, 88);
        scope.Complete();
    }
}
