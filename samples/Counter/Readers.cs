using MicroCard.Framework;
[CardAssembly("F04D430002")]
public static class Reader {
 public static void Process(){int value=SecurityDomain.Current.Store.GetInt32(1);byte[] response=[(byte)value,(byte)(value>>8),(byte)(value>>16),(byte)(value>>24)];ResponseApdu.Write(response,0,response.Length);}
}
[CardAssembly("F04D430003")]
public static class Echo {
 public static void Process(){var response=new byte[CommandApdu.Length];CommandApdu.CopyTo(response,0,0,response.Length);ResponseApdu.Write(response,0,response.Length);}
}
[CardAssembly("F04D430004")]
public static class ProtectedCommand {
 public static void Process(){if((SecureChannel.SecurityLevel&0x13)!=0x13){ResponseApdu.SetStatus(0x6982);return;}var data=new byte[1];data[0]=0x61;var digest=Cryptography.Sha256(data);ResponseApdu.Write(digest,0,1);}
}
