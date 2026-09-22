namespace MicroCard.Framework;
[AttributeUsage(AttributeTargets.Class)] public sealed class AssemblyAttribute(string aid) : Attribute { public string Aid { get; } = aid; }
[AttributeUsage(AttributeTargets.Method)] public sealed class InstallAttribute : Attribute { }
[AttributeUsage(AttributeTargets.Method)] public sealed class SelectAttribute : Attribute { }
[AttributeUsage(AttributeTargets.Method)] public sealed class DeselectAttribute : Attribute { }
[AttributeUsage(AttributeTargets.Method)] public sealed class ProcessAttribute : Attribute { }
[AttributeUsage(AttributeTargets.Method)] public sealed class UninstallAttribute : Attribute { }
public enum DependencyAccess { Private = 0, Any = 1, SameSigner = 2, SpecificPublicKey = 3 }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
public sealed class DependencyExportAttribute : Attribute {
 public DependencyExportAttribute(DependencyAccess access) { if (access is DependencyAccess.Private or DependencyAccess.SpecificPublicKey) throw new ArgumentException("Use Any, SameSigner, or the public-key constructor", nameof(access)); Access = access; }
 public DependencyExportAttribute(string publicKeyHex) { Access = DependencyAccess.SpecificPublicKey; PublicKeyHex = publicKeyHex; }
 public DependencyAccess Access { get; }
 public string? PublicKeyHex { get; }
}
public enum DependencyScope { SameSecurityDomain = 0, IssuerSecurityDomain = 1, SameOrIssuer = 2 }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
public sealed class DeviceAssemblyIdentityAttribute(string name) : Attribute {
 public string Name { get; } = name;
}
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class PersistentInt32Attribute(int key) : Attribute {
 public int Key { get; } = key;
}
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class PersistentBytesAttribute(int key, int maxLength) : Attribute {
 public int Key { get; } = key;
 public int MaxLength { get; } = maxLength;
}
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class DependencyAttribute(string assembly, string versionConstraint) : Attribute {
 public string Assembly { get; } = assembly;
 public string VersionConstraint { get; } = versionConstraint;
 public string? ReferenceAssembly { get; set; }
 public uint PackageVersion { get; set; }
 public string? PackageDigestHex { get; set; }
 public string? SignerPublicKeyHex { get; set; }
 public DependencyScope Scope { get; set; } = DependencyScope.SameOrIssuer;
}
// Host implementation permits differential execution. The preprocessor binds only this pinned assembly.
public interface IHost { int CommandLength { get; } void CopyCommandTo(byte[] destination,int destinationOffset,int sourceOffset,int length); void WriteResponse(byte[] source,int sourceOffset,int length); void Status(int value); int Get(int key); void Set(int key,int value); byte[] GetBytes(int key); void SetBytes(int key,byte[] value); void SetBytes(int key,byte[] value,int offset,int length); void DeleteBytes(int key); bool ContainsBytes(int key); int Random(); void FillRandom(byte[] destination,int offset,int length); int SecurityLevel { get; } byte[] GenerateKey(int slot,int algorithm); byte[] OpenKey(int slot); void DeleteKey(int slot); byte[] KeyOperation(int operation,byte[] token,byte[][] data); byte[] KeyOperation(int operation,byte[] token,byte[] data,int offset,int length); bool P256Verify(byte[] publicKey,byte[] data,byte[] signature); void CreateCredential(int slot,byte[] pin,int pinOffset,int pinLength,int pinRetries,byte[] puk,int pukOffset,int pukLength,int pukRetries); bool VerifyCredential(int slot,byte[] candidate,int offset,int length); bool IsCredentialVerified(int slot); void ChangeCredential(int slot,byte[] newPin,int offset,int length); bool UnblockCredential(int slot,byte[] puk,int pukOffset,int pukLength,byte[] newPin,int newPinOffset,int newPinLength); int CredentialRetries(int slot,int kind); void Gpio(int resource,int value); }
public static class Host { public static IHost? Current { get; set; } internal static IHost Required => Current ?? throw new InvalidOperationException("No host context"); }
public static class CommandApdu { public static int Length => Host.Required.CommandLength; public static void CopyTo(byte[] destination,int destinationOffset,int sourceOffset,int length) => Host.Required.CopyCommandTo(destination,destinationOffset,sourceOffset,length); }
public static class ResponseApdu { public static void Write(byte[] source,int sourceOffset,int length) => Host.Required.WriteResponse(source,sourceOffset,length); public static void SetStatus(int value) => Host.Required.Status(value); }
public static class DomainStore { public static int GetInt32(int key) => Host.Required.Get(key); public static void SetInt32(int key,int value) => Host.Required.Set(key,value); }
public static class RandomNumber { public static int GetInt32() => Host.Required.Random(); }
public static class Hardware { public static void Write(int resource,int value) => Host.Required.Gpio(resource,value); }

public sealed class SecurityDomain {
 private SecurityDomain() { }
 public static SecurityDomain Current { get; } = new();
 public DomainStorage Store { get; } = new();
 public DomainKeys Keys { get; } = new();
}
public sealed class DomainStorage {
 internal DomainStorage() { }
 public int GetInt32(int key) => DomainStore.GetInt32(key);
 public void SetInt32(int key,int value) => DomainStore.SetInt32(key,value);
 public byte[] GetBytes(int key) => Host.Required.GetBytes(key);
 public void SetBytes(int key,byte[] value) => Host.Required.SetBytes(key,value);
 public void SetBytes(int key,byte[] value,int offset,int length) => Host.Required.SetBytes(key,value,offset,length);
 public void DeleteBytes(int key) => Host.Required.DeleteBytes(key);
 public bool ContainsBytes(int key) => Host.Required.ContainsBytes(key);
}

public static class SecureChannel {
 public static int SecurityLevel => Host.Required.SecurityLevel;
 public static bool IsAuthenticated => SecurityLevel != 0;
}

public static class Cryptography {
 public static byte[] Sha256(byte[] input) => System.Security.Cryptography.SHA256.HashData(input);
 public static int Sha256Into(byte[] input,int inputOffset,int inputLength,byte[] destination,int destinationOffset) {
  if (inputOffset < 0 || inputLength < 0 || inputOffset > input.Length - inputLength) throw new ArgumentOutOfRangeException(nameof(inputOffset));
  if (destinationOffset < 0 || destinationOffset > destination.Length - 32) throw new ArgumentOutOfRangeException(nameof(destinationOffset));
  if (!System.Security.Cryptography.SHA256.TryHashData(input.AsSpan(inputOffset,inputLength),destination.AsSpan(destinationOffset,32),out int written) || written != 32) throw new InvalidOperationException("SHA-256 output");
  return written;
 }
 public static bool VerifyP256(byte[] publicKey,byte[] data,byte[] signature) => Host.Required.P256Verify(publicKey,data,signature);
 public static void FillRandom(byte[] destination,int offset,int length) => Host.Required.FillRandom(destination,offset,length);
 public static byte[] RandomBytes(int length) {
  if (length < 0 || length > 1024) throw new ArgumentOutOfRangeException(nameof(length));
  return System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
 }
 public static bool FixedTimeEquals(byte[] left,int leftOffset,int leftLength,byte[] right,int rightOffset,int rightLength) {
  if (leftOffset < 0 || leftLength < 0 || leftLength > 1024 || leftOffset > left.Length - leftLength) throw new ArgumentOutOfRangeException(nameof(leftOffset));
  if (rightOffset < 0 || rightLength < 0 || rightLength > 1024 || rightOffset > right.Length - rightLength) throw new ArgumentOutOfRangeException(nameof(rightOffset));
  return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left.AsSpan(leftOffset,leftLength),right.AsSpan(rightOffset,rightLength));
 }
}

public static class CredentialNative {
 public static void Create(int slot,byte[] pin,int pinOffset,int pinLength,int pinRetries,byte[] puk,int pukOffset,int pukLength,int pukRetries) => Host.Required.CreateCredential(slot,pin,pinOffset,pinLength,pinRetries,puk,pukOffset,pukLength,pukRetries);
 public static bool Verify(int slot,byte[] candidate,int offset,int length) => Host.Required.VerifyCredential(slot,candidate,offset,length);
 public static bool IsVerified(int slot) => Host.Required.IsCredentialVerified(slot);
 public static void Change(int slot,byte[] newPin,int offset,int length) => Host.Required.ChangeCredential(slot,newPin,offset,length);
 public static bool Unblock(int slot,byte[] puk,int pukOffset,int pukLength,byte[] newPin,int newPinOffset,int newPinLength) => Host.Required.UnblockCredential(slot,puk,pukOffset,pukLength,newPin,newPinOffset,newPinLength);
 public static int RetriesRemaining(int slot,int kind) => Host.Required.CredentialRetries(slot,kind);
}

public sealed class DomainKeys {
 internal DomainKeys() { }
 public KeyHandle Generate(int slot,int algorithm) => new(Host.Required.GenerateKey(slot,algorithm));
 public KeyHandle Open(int slot) => new(Host.Required.OpenKey(slot));
 public void Delete(int slot) => Host.Required.DeleteKey(slot);
}
public sealed class KeyHandle {
 private readonly byte[] token;
 internal KeyHandle(byte[] token) { this.token=token; }
 public byte[] HmacSha256(byte[] input) => Host.Required.KeyOperation(25,token,[input]);
 public byte[] AesCmac(byte[] input) => Host.Required.KeyOperation(26,token,[input]);
 public byte[] EncryptCbc(byte[] iv,byte[] input) => Host.Required.KeyOperation(27,token,[iv,input]);
 public byte[] DecryptCbc(byte[] iv,byte[] input) => Host.Required.KeyOperation(28,token,[iv,input]);
 public byte[] EncryptCcm(byte[] nonce,byte[] aad,byte[] input) => Host.Required.KeyOperation(29,token,[nonce,aad,input]);
 public byte[] DecryptCcm(byte[] nonce,byte[] aad,byte[] input) => Host.Required.KeyOperation(30,token,[nonce,aad,input]);
 public byte[] ExportP256PublicKey() => Host.Required.KeyOperation(35,token,[]);
 public byte[] SignP256(byte[] input,int offset,int length) => Host.Required.KeyOperation(36,token,input,offset,length);
 public byte[] DeriveP256(byte[] peerPublicKey) => Host.Required.KeyOperation(38,token,[peerPublicKey]);
}

public static class KeyAlgorithms { public const int HmacSha256=1; public const int Aes128=2; public const int P256=3; }


public static class Buffers
{
    public static bool Copy(byte[] source, int sourceOffset, byte[] destination,
        int destinationOffset, int length)
    {
        if (sourceOffset < 0 || destinationOffset < 0 || length < 0 ||
            sourceOffset > source.Length || length > source.Length - sourceOffset ||
            destinationOffset > destination.Length || length > destination.Length - destinationOffset)
            return false;
        System.Array.Copy(source, sourceOffset, destination, destinationOffset, length);
        return true;
    }
}
