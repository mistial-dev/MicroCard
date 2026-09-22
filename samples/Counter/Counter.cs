using MicroCard.Framework;
[assembly: PersistentInt32(1)]
[CardAssembly("F04D430001")]
public static class Counter {
 public static void Install() { AssemblyContext.Current.Storage.SetInt32((StorageId)1,0); }
 public static void Process() { int next=checked(AssemblyContext.Current.Storage.GetInt32((StorageId)1)+1); AssemblyContext.Current.Storage.SetInt32((StorageId)1,next); byte[] response=[(byte)next];AssemblyContext.Current.Response.Write(response,0,1); }
 public static int Arithmetic(int a,int b) { return checked(a*3+b); }
}
