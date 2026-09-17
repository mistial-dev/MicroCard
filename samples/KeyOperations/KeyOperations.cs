using MicroCard.Framework;
[assembly: PersistentInt32(10)]
[assembly: PersistentBytes(20, 3)]
[assembly: PersistentBytes(21, 1)]
[assembly: PersistentInt32(30)]
[Assembly("F04D430010")]
public static class KeyOperations {
 [Install] public static void Install(){SecurityDomain.Current.Keys.Generate(0,KeyAlgorithms.HmacSha256);SecurityDomain.Current.Keys.Generate(1,KeyAlgorithms.Aes128);SecurityDomain.Current.Store.SetInt32(10,0);}
 [Process] public static void Process(){
  var message=new byte[1];message[0]=97;int inputLength=CommandApdu.Length;if(inputLength<1){ResponseApdu.SetStatus(0x6700);return;}var input=new byte[inputLength];CommandApdu.CopyTo(input,0,0,input.Length);int command=input[0];
  if(command==0){Write(SecurityDomain.Current.Keys.Open(0).HmacSha256(message));return;}
  var key=SecurityDomain.Current.Keys.Open(1);
  if(command==1){Write(key.AesCmac(message));return;}
  if(command==2){var iv=new byte[16];for(int i=0;i<16;i++)iv[i]=(byte)RandomNumber.GetInt32();Write(key.DecryptCbc(iv,key.EncryptCbc(iv,message)));return;}
  if(command==3){var nonce=new byte[13];for(int i=0;i<13;i++)nonce[i]=(byte)RandomNumber.GetInt32();var aad=new byte[0];Write(key.DecryptCcm(nonce,aad,key.EncryptCcm(nonce,aad,message)));return;}
  if(command==4){var stale=SecurityDomain.Current.Keys.Open(0);SecurityDomain.Current.Keys.Delete(0);SecurityDomain.Current.Keys.Generate(0,KeyAlgorithms.HmacSha256);Write(stale.HmacSha256(message));return;}
  ResponseApdu.SetStatus(0x6D00);
 }
 public static void Write(byte[] data){ResponseApdu.Write(data,0,data.Length);}
}
[Assembly("F04D430011")]
public static class KeyReader {
 [Process] public static void Process(){var input=new byte[1];input[0]=97;SecurityDomain.Current.Store.SetInt32(10,checked(SecurityDomain.Current.Store.GetInt32(10)+1));KeyOperations.Write(SecurityDomain.Current.Keys.Open(0).HmacSha256(input));}
}
[Assembly("F04D430012")]
public static class BlobRecords {
 [Process] public static void Process(){
  int inputLength=CommandApdu.Length;if(inputLength<1){ResponseApdu.SetStatus(0x6700);return;}var input=new byte[inputLength];CommandApdu.CopyTo(input,0,0,input.Length);int command=input[0];
  if(command==0){var value=new byte[3];value[0]=98;value[1]=108;value[2]=111;SecurityDomain.Current.Store.SetBytes(20,value);return;}
  if(command==1){var value=SecurityDomain.Current.Store.GetBytes(20);ResponseApdu.Write(value,0,value.Length);return;}
  if(command==2){byte[] response=[SecurityDomain.Current.Store.ContainsBytes(20)?(byte)1:(byte)0];ResponseApdu.Write(response,0,1);return;}
  if(command==3){SecurityDomain.Current.Store.DeleteBytes(20);return;}
  if(command==4){var value=new byte[1];value[0]=1;SecurityDomain.Current.Store.SetBytes(21,value);int impossible=checked(2147483647+command);byte[] response=[(byte)impossible];ResponseApdu.Write(response,0,1);return;}
  if(command==5){byte[] response=[SecurityDomain.Current.Store.ContainsBytes(21)?(byte)1:(byte)0];ResponseApdu.Write(response,0,1);return;}
  ResponseApdu.SetStatus(0x6D00);
 }
}

[Assembly("F04D430013")]
public static class BudgetLoop {
 [Process, Transaction] public static void Process(){SecurityDomain.Current.Store.SetInt32(30,1);for(;;){}}
}
