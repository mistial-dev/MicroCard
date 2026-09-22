namespace MicroCard.Framework.Testing;

/// <summary>Desktop-only host contract for differential tests of managed assembly code.</summary>
public interface IAssemblyContextTestHost
{
    int CommandLength { get; }
    void CopyCommandTo(byte[] destination, int destinationOffset, int sourceOffset, int length);
    void WriteResponse(byte[] source, int sourceOffset, int length);
    void Status(int value);
    int Get(int key);
    void Set(int key, int value);
    byte[] GetBytes(int key);
    void SetBytes(int key, byte[] value);
    void SetBytes(int key, byte[] value, int offset, int length);
    void DeleteBytes(int key);
    bool ContainsBytes(int key);
    int Random();
    void FillRandom(byte[] destination, int offset, int length);
    int SecurityLevel { get; }
    byte[] GenerateKey(int slot, int algorithm);
    byte[] OpenKey(int slot);
    void DeleteKey(int slot);
    byte[] KeyOperation(int operation, byte[] token, byte[][] data);
    byte[] KeyOperation(int operation, byte[] token, byte[] data, int offset, int length);
    bool P256Verify(byte[] publicKey, byte[] data, byte[] signature);
    void CreateCredential(int slot, byte[] pin, int pinOffset, int pinLength, int pinRetries, byte[] puk, int pukOffset, int pukLength, int pukRetries);
    bool VerifyCredential(int slot, byte[] candidate, int offset, int length);
    bool IsCredentialVerified(int slot);
    void ChangeCredential(int slot, byte[] newPin, int offset, int length);
    bool UnblockCredential(int slot, byte[] puk, int pukOffset, int pukLength, byte[] newPin, int newPinOffset, int newPinLength);
    int CredentialRetries(int slot, int kind);
    void Gpio(int resource, int value);
}

/// <summary>Installs a desktop test host without exposing mutable host state to assemblies.</summary>
public static class AssemblyContextTesting
{
    public static void Use(IAssemblyContextTestHost host) => RuntimeBridge.Current = host ?? throw new ArgumentNullException(nameof(host));
    public static void Clear() => RuntimeBridge.Current = null;
}
