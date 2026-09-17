using MicroCard.Framework;
[assembly: PersistentInt32(1)]
[Assembly("F04D430001")]
public static class Counter {
 [Install] public static void Install() { SecurityDomain.Current.Store.SetInt32(1,0); }
 [Process, Transaction] public static void Process() { int next=checked(SecurityDomain.Current.Store.GetInt32(1)+1); SecurityDomain.Current.Store.SetInt32(1,next); byte[] response=[(byte)next];ResponseApdu.Write(response,0,1); }
 public static int Arithmetic(int a,int b) { return checked(a*3+b); }
}
