using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Security;

public static class Pin
{
    public static void Create(CredentialSlot slot, byte[] pin, int pinRetries, byte[] puk, int pukRetries) =>
        Create(slot, pin, 0, pin.Length, pinRetries, puk, 0, puk.Length, pukRetries);

    public static void Create(CredentialSlot slot, byte[] pin, int pinOffset, int pinLength, int pinRetries,
        byte[] puk, int pukOffset, int pukLength, int pukRetries) =>
        AssemblyContext.Current.Credentials.Create(slot, pin, pinOffset, pinLength, pinRetries, puk, pukOffset,
            pukLength, pukRetries);

    public static bool Verify(CredentialSlot slot, byte[] candidate) =>
        Verify(slot, candidate, 0, candidate.Length);

    public static bool Verify(CredentialSlot slot, byte[] candidate, int offset, int length) =>
        AssemblyContext.Current.Credentials.Verify(slot, candidate, offset, length);

    public static bool IsVerified(CredentialSlot slot) => AssemblyContext.Current.Credentials.IsVerified(slot);

    public static void Change(CredentialSlot slot, byte[] newPin) => Change(slot, newPin, 0, newPin.Length);

    public static void Change(CredentialSlot slot, byte[] newPin, int offset, int length) =>
        AssemblyContext.Current.Credentials.Change(slot, newPin, offset, length);

    public static bool Unblock(CredentialSlot slot, byte[] puk, byte[] newPin) =>
        Unblock(slot, puk, 0, puk.Length, newPin, 0, newPin.Length);

    public static bool Unblock(CredentialSlot slot, byte[] puk, int pukOffset, int pukLength, byte[] newPin,
        int newPinOffset, int newPinLength) =>
        AssemblyContext.Current.Credentials.Unblock(slot, puk, pukOffset, pukLength, newPin, newPinOffset,
            newPinLength);

    public static int RetriesRemaining(CredentialSlot slot) => AssemblyContext.Current.Credentials.RetriesRemaining(slot, 0);

    public static int PukRetriesRemaining(CredentialSlot slot) => AssemblyContext.Current.Credentials.RetriesRemaining(slot, 1);
}
