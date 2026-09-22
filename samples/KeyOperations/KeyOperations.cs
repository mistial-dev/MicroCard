using MicroCard.Framework;
[assembly: PersistentInt32(10)]
[assembly: PersistentBytes(20, 3)]
[assembly: PersistentBytes(21, 1)]
[assembly: PersistentInt32(30)]
[CardAssembly("F04D430010")]
public static class KeyOperations {
 public static void Install(){AssemblyContext.Current.Keys.Generate((KeySlot)0,KeyAlgorithm.HmacSha256);AssemblyContext.Current.Keys.Generate((KeySlot)1,KeyAlgorithm.Aes128);AssemblyContext.Current.Storage.SetInt32((StorageId)10,0);}
 public static void Process(){
  var message=new byte[1];message[0]=97;int inputLength=AssemblyContext.Current.Command.Length;if(inputLength<1){AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);return;}var input=new byte[inputLength];AssemblyContext.Current.Command.CopyTo(input,0,0,input.Length);int command=input[0];
  if(command==0){Write(AssemblyContext.Current.Keys.Open((KeySlot)0).HmacSha256(message));return;}
  var key=AssemblyContext.Current.Keys.Open((KeySlot)1);
  if(command==1){Write(key.AesCmac(message));return;}
  if(command==2){var iv=new byte[16];for(int i=0;i<16;i++)iv[i]=(byte)AssemblyContext.Current.Random.GetInt32();Write(key.DecryptCbc(iv,key.EncryptCbc(iv,message)));return;}
  if(command==3){var nonce=new byte[13];for(int i=0;i<13;i++)nonce[i]=(byte)AssemblyContext.Current.Random.GetInt32();var aad=new byte[0];Write(key.DecryptCcm(nonce,aad,key.EncryptCcm(nonce,aad,message)));return;}
  if(command==4){var stale=AssemblyContext.Current.Keys.Open((KeySlot)0);AssemblyContext.Current.Keys.Delete((KeySlot)0);AssemblyContext.Current.Keys.Generate((KeySlot)0,KeyAlgorithm.HmacSha256);Write(stale.HmacSha256(message));return;}
  AssemblyContext.Current.Response.SetStatus((StatusWord)0x6D00);
 }
 public static void Write(byte[] data){AssemblyContext.Current.Response.Write(data,0,data.Length);}
}
[CardAssembly("F04D430011")]
public static class KeyReader {
 public static void Process(){var input=new byte[1];input[0]=97;AssemblyContext.Current.Storage.SetInt32((StorageId)10,checked(AssemblyContext.Current.Storage.GetInt32((StorageId)10)+1));KeyOperations.Write(AssemblyContext.Current.Keys.Open((KeySlot)0).HmacSha256(input));}
}
[CardAssembly("F04D430012")]
public static class BlobRecords {
 public static void Process(){
  int inputLength=AssemblyContext.Current.Command.Length;if(inputLength<1){AssemblyContext.Current.Response.SetStatus((StatusWord)0x6700);return;}var input=new byte[inputLength];AssemblyContext.Current.Command.CopyTo(input,0,0,input.Length);int command=input[0];
  if(command==0){var value=new byte[3];value[0]=98;value[1]=108;value[2]=111;AssemblyContext.Current.Storage.SetBytes((StorageId)20,value);return;}
  if(command==1){var value=AssemblyContext.Current.Storage.GetBytes((StorageId)20);AssemblyContext.Current.Response.Write(value,0,value.Length);return;}
  if(command==2){byte[] response=[AssemblyContext.Current.Storage.ContainsBytes((StorageId)20)?(byte)1:(byte)0];AssemblyContext.Current.Response.Write(response,0,1);return;}
  if(command==3){AssemblyContext.Current.Storage.DeleteBytes((StorageId)20);return;}
  if(command==4){var value=new byte[1];value[0]=1;AssemblyContext.Current.Storage.SetBytes((StorageId)21,value);int impossible=checked(2147483647+command);byte[] response=[(byte)impossible];AssemblyContext.Current.Response.Write(response,0,1);return;}
  if(command==5){byte[] response=[AssemblyContext.Current.Storage.ContainsBytes((StorageId)21)?(byte)1:(byte)0];AssemblyContext.Current.Response.Write(response,0,1);return;}
  AssemblyContext.Current.Response.SetStatus((StatusWord)0x6D00);
 }
}

[CardAssembly("F04D430013")]
public static class BudgetLoop {
 public static void Process(){AssemblyContext.Current.Storage.SetInt32((StorageId)30,1);for(;;){}}
}
