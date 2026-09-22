using MicroCard.Framework;
using System.Transactions;
[assembly: PersistentInt32(1)]
[Assembly("F04D430001")]
public static class Counter {
 [Install] public static void Install() { SecurityDomain.Current.Store.SetInt32(1,0); }
 [Process] public static void Process() { using var scope=new TransactionScope(); int next=checked(SecurityDomain.Current.Store.GetInt32(1)+1); SecurityDomain.Current.Store.SetInt32(1,next); byte[] response=[(byte)next];ResponseApdu.Write(response,0,1); scope.Complete(); }
 public static int Arithmetic(int a,int b) { return checked(a*3+b); }
}
