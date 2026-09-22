namespace MicroCard.Framework;

/// <summary>Declares the static class that implements one MC04 card assembly.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class CardAssemblyAttribute(string aid) : Attribute
{
    /// <summary>Gets the hexadecimal application identifier selected by the host.</summary>
    public string Aid { get; } = aid;
}

public enum DependencyAccess { Private = 0, Any = 1, SameSigner = 2, SpecificPublicKey = 3 }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
public sealed class DependencyExportAttribute : Attribute
{
    public DependencyExportAttribute(DependencyAccess access) { if (access is DependencyAccess.Private or DependencyAccess.SpecificPublicKey) throw new ArgumentException("Use Any, SameSigner, or the public-key constructor", nameof(access)); Access = access; }
    public DependencyExportAttribute(string publicKeyHex) { Access = DependencyAccess.SpecificPublicKey; PublicKeyHex = publicKeyHex; }
    public DependencyAccess Access { get; }
    public string? PublicKeyHex { get; }
}
public enum DependencyScope { SameSecurityDomain = 0, IssuerSecurityDomain = 1, SameOrIssuer = 2 }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
public sealed class DeviceAssemblyIdentityAttribute(string name) : Attribute { public string Name { get; } = name; }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class PersistentInt32Attribute(int key) : Attribute { public int Key { get; } = key; }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class PersistentBytesAttribute(int key, int maxLength) : Attribute { public int Key { get; } = key; public int MaxLength { get; } = maxLength; }
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class DependencyAttribute(string assembly, string versionConstraint) : Attribute
{
    public string Assembly { get; } = assembly;
    public string VersionConstraint { get; } = versionConstraint;
    public string? ReferenceAssembly { get; set; }
    public uint PackageVersion { get; set; }
    public string? PackageDigestHex { get; set; }
    public string? SignerPublicKeyHex { get; set; }
    public DependencyScope Scope { get; set; } = DependencyScope.SameOrIssuer;
}

/// <summary>An application-defined persistent storage identifier.</summary>
public enum StorageId : int { }
/// <summary>An application-defined key slot.</summary>
public enum KeySlot : int { }
/// <summary>An application-defined credential slot.</summary>
public enum CredentialSlot : int { }
/// <summary>A key algorithm supported by MC04.</summary>
public enum KeyAlgorithm : int { HmacSha256 = 1, Aes128 = 2, P256 = 3 }
/// <summary>ISO/IEC 7816 response status words commonly used by assemblies.</summary>
public enum StatusWord : int
{
    Success = 0x9000, WarningStateUnchanged = 0x6200, WarningStateChanged = 0x6300,
    WrongLength = 0x6700, SecurityStatusNotSatisfied = 0x6982,
    AuthenticationMethodBlocked = 0x6983, ConditionsNotSatisfied = 0x6985,
    IncorrectData = 0x6A80, FunctionNotSupported = 0x6A81, FileNotFound = 0x6A82,
    RecordNotFound = 0x6A83, NotEnoughMemory = 0x6A84, IncorrectParameters = 0x6A86,
    ReferenceDataNotFound = 0x6A88, WrongParameters = 0x6B00,
    InstructionNotSupported = 0x6D00, ClassNotSupported = 0x6E00, UnknownError = 0x6F00,
}
/// <summary>The authenticated protections on the current command.</summary>
[Flags]
public enum SecurityLevel : int
{
    None = 0, CommandAuthentication = 0x01, CommandEncryption = 0x02,
    ResponseAuthentication = 0x10, ResponseEncryption = 0x20,
}

/// <summary>Provides the services available to the currently executing assembly.</summary>
public sealed class AssemblyContext
{
    private AssemblyContext() { }
    /// <summary>Gets the context for the current invocation.</summary>
    public static AssemblyContext Current { get; } = new();
    public CommandService Command { get; } = new();
    public ResponseService Response { get; } = new();
    public StorageService Storage { get; } = new();
    public KeyService Keys { get; } = new();
    public RandomService Random { get; } = new();
    public SecureChannelService SecureChannel { get; } = new();
    public CredentialService Credentials { get; } = new();
    public RuntimeService Runtime { get; } = new();
}

/// <summary>Reads the current command APDU.</summary>
public sealed class CommandService
{
    internal CommandService() { }
    public int Length => RuntimeBridge.Host.CommandLength;
    public void CopyTo(byte[] destination, int destinationOffset, int sourceOffset, int length) => RuntimeBridge.Host.CopyCommandTo(destination, destinationOffset, sourceOffset, length);
}
/// <summary>Builds the current response APDU.</summary>
public sealed class ResponseService
{
    internal ResponseService() { }
    public void Write(byte[] source, int sourceOffset, int length) => RuntimeBridge.Host.WriteResponse(source, sourceOffset, length);
    public void SetStatus(StatusWord value) => RuntimeBridge.Host.Status((int)value);
}
/// <summary>Reads and updates the current security domain's persistent storage.</summary>
public sealed class StorageService
{
    internal StorageService() { }
    public int GetInt32(StorageId id) => RuntimeBridge.Host.Get((int)id);
    public void SetInt32(StorageId id, int value) => RuntimeBridge.Host.Set((int)id, value);
    public byte[] GetBytes(StorageId id) => RuntimeBridge.Host.GetBytes((int)id);
    public void SetBytes(StorageId id, byte[] value) => RuntimeBridge.Host.SetBytes((int)id, value);
    public void SetBytes(StorageId id, byte[] value, int offset, int length) => RuntimeBridge.Host.SetBytes((int)id, value, offset, length);
    public void DeleteBytes(StorageId id) => RuntimeBridge.Host.DeleteBytes((int)id);
    public bool ContainsBytes(StorageId id) => RuntimeBridge.Host.ContainsBytes((int)id);
}
/// <summary>Manages opaque keys owned by the current security domain.</summary>
public sealed class KeyService
{
    internal KeyService() { }
    public KeyHandle Generate(KeySlot slot, KeyAlgorithm algorithm) => new(RuntimeBridge.Host.GenerateKey((int)slot, (int)algorithm));
    public KeyHandle Open(KeySlot slot) => new(RuntimeBridge.Host.OpenKey((int)slot));
    public void Delete(KeySlot slot) => RuntimeBridge.Host.DeleteKey((int)slot);
}
/// <summary>Provides random values for the current invocation.</summary>
public sealed class RandomService
{
    internal RandomService() { }
    public int GetInt32() => RuntimeBridge.Host.Random();
    public void Fill(byte[] destination, int offset, int length) => RuntimeBridge.Host.FillRandom(destination, offset, length);
    public byte[] GetBytes(int length)
    {
        if (length < 0 || length > 1024) throw new ArgumentOutOfRangeException(nameof(length));
        var result = new byte[length];
        if (RuntimeBridge.Current is { } host)
            host.FillRandom(result, 0, result.Length);
        else
            System.Security.Cryptography.RandomNumberGenerator.Fill(result);
        return result;
    }
}
/// <summary>Describes the authenticated secure channel for the current command.</summary>
public sealed class SecureChannelService
{
    internal SecureChannelService() { }
    public SecurityLevel SecurityLevel => (SecurityLevel)RuntimeBridge.Host.SecurityLevel;
    public bool IsAuthenticated => SecurityLevel != MicroCard.Framework.SecurityLevel.None;
}
/// <summary>Manages application credentials in the current security domain.</summary>
public sealed class CredentialService
{
    internal CredentialService() { }
    public void Create(CredentialSlot slot, byte[] pin, int pinOffset, int pinLength, int pinRetries, byte[] puk, int pukOffset, int pukLength, int pukRetries) => RuntimeBridge.Host.CreateCredential((int)slot, pin, pinOffset, pinLength, pinRetries, puk, pukOffset, pukLength, pukRetries);
    public bool Verify(CredentialSlot slot, byte[] candidate, int offset, int length) => RuntimeBridge.Host.VerifyCredential((int)slot, candidate, offset, length);
    public bool IsVerified(CredentialSlot slot) => RuntimeBridge.Host.IsCredentialVerified((int)slot);
    public void Change(CredentialSlot slot, byte[] newPin, int offset, int length) => RuntimeBridge.Host.ChangeCredential((int)slot, newPin, offset, length);
    public bool Unblock(CredentialSlot slot, byte[] puk, int pukOffset, int pukLength, byte[] newPin, int newPinOffset, int newPinLength) => RuntimeBridge.Host.UnblockCredential((int)slot, puk, pukOffset, pukLength, newPin, newPinOffset, newPinLength);
    public int RetriesRemaining(CredentialSlot slot, int kind) => RuntimeBridge.Host.CredentialRetries((int)slot, kind);
}
/// <summary>Provides runtime primitives that do not belong to a domain service.</summary>
public sealed class RuntimeService
{
    internal RuntimeService() { }
    public void WriteHardware(int resource, int value) => RuntimeBridge.Host.Gpio(resource, value);
    public byte[] Sha256(byte[] input) => System.Security.Cryptography.SHA256.HashData(input);
    public int Sha256Into(byte[] input, int inputOffset, int inputLength, byte[] destination, int destinationOffset)
    {
        if (inputOffset < 0 || inputLength < 0 || inputOffset > input.Length - inputLength) throw new ArgumentOutOfRangeException(nameof(inputOffset));
        if (destinationOffset < 0 || destinationOffset > destination.Length - 32) throw new ArgumentOutOfRangeException(nameof(destinationOffset));
        if (!System.Security.Cryptography.SHA256.TryHashData(input.AsSpan(inputOffset, inputLength), destination.AsSpan(destinationOffset, 32), out int written) || written != 32) throw new InvalidOperationException("SHA-256 output");
        return written;
    }
    public bool VerifyP256(byte[] publicKey, byte[] data, byte[] signature) => RuntimeBridge.Host.P256Verify(publicKey, data, signature);
    public bool FixedTimeEquals(byte[] left, int leftOffset, int leftLength, byte[] right, int rightOffset, int rightLength)
    {
        if (leftOffset < 0 || leftLength < 0 || leftLength > 1024 || leftOffset > left.Length - leftLength) throw new ArgumentOutOfRangeException(nameof(leftOffset));
        if (rightOffset < 0 || rightLength < 0 || rightLength > 1024 || rightOffset > right.Length - rightLength) throw new ArgumentOutOfRangeException(nameof(rightOffset));
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left.AsSpan(leftOffset, leftLength), right.AsSpan(rightOffset, rightLength));
    }
}
/// <summary>An opaque handle to a key in the current security domain.</summary>
public sealed class KeyHandle
{
    private readonly byte[] token;
    internal KeyHandle(byte[] token) => this.token = token;
    public byte[] HmacSha256(byte[] input) => RuntimeBridge.Host.KeyOperation(25, token, [input]);
    public byte[] AesCmac(byte[] input) => RuntimeBridge.Host.KeyOperation(26, token, [input]);
    public byte[] EncryptCbc(byte[] iv, byte[] input) => RuntimeBridge.Host.KeyOperation(27, token, [iv, input]);
    public byte[] DecryptCbc(byte[] iv, byte[] input) => RuntimeBridge.Host.KeyOperation(28, token, [iv, input]);
    public byte[] EncryptCcm(byte[] nonce, byte[] aad, byte[] input) => RuntimeBridge.Host.KeyOperation(29, token, [nonce, aad, input]);
    public byte[] DecryptCcm(byte[] nonce, byte[] aad, byte[] input) => RuntimeBridge.Host.KeyOperation(30, token, [nonce, aad, input]);
    public byte[] ExportP256PublicKey() => RuntimeBridge.Host.KeyOperation(35, token, []);
    public byte[] SignP256(byte[] input, int offset, int length) => RuntimeBridge.Host.KeyOperation(36, token, input, offset, length);
    public byte[] DeriveP256(byte[] peerPublicKey) => RuntimeBridge.Host.KeyOperation(38, token, [peerPublicKey]);
}

internal static class RuntimeBridge
{
    internal static Testing.IAssemblyContextTestHost? Current { get; set; }
    internal static Testing.IAssemblyContextTestHost Host => Current ?? throw new InvalidOperationException("No assembly context");
}

public static class Buffers
{
    public static bool Copy(byte[] source, int sourceOffset, byte[] destination, int destinationOffset, int length)
    {
        if (sourceOffset < 0 || destinationOffset < 0 || length < 0 || sourceOffset > source.Length || length > source.Length - sourceOffset || destinationOffset > destination.Length || length > destination.Length - destinationOffset) return false;
        System.Array.Copy(source, sourceOffset, destination, destinationOffset, length);
        return true;
    }
}
