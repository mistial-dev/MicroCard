using MicroCard.Framework;
[CardAssembly("F04D430002")]
public static class Reader {
 public static void Process(){int value=AssemblyContext.Current.Storage.GetInt32((StorageId)1);byte[] response=[(byte)value,(byte)(value>>8),(byte)(value>>16),(byte)(value>>24)];AssemblyContext.Current.Response.Write(response,0,response.Length);}
}
[CardAssembly("F04D430003")]
public static class Echo {
 public static void Process(){var response=new byte[AssemblyContext.Current.Command.Length];AssemblyContext.Current.Command.CopyTo(response,0,0,response.Length);AssemblyContext.Current.Response.Write(response,0,response.Length);}
}
[CardAssembly("F04D430004")]
public static class ProtectedCommand {
 public static void Process(){if(((int)AssemblyContext.Current.SecureChannel.SecurityLevel & 0x13)!=0x13){AssemblyContext.Current.Response.SetStatus((StatusWord)0x6982);return;}var data=new byte[1];data[0]=0x61;var digest=AssemblyContext.Current.Runtime.Sha256(data);AssemblyContext.Current.Response.Write(digest,0,1);}
}
