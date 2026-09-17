using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Security;

public static class Pin
{
    public static void Create(int slot, byte[] pin, int pinRetries, byte[] puk, int pukRetries) =>
        Create(slot, pin, 0, pin.Length, pinRetries, puk, 0, puk.Length, pukRetries);

    public static void Create(int slot, byte[] pin, int pinOffset, int pinLength, int pinRetries,
        byte[] puk, int pukOffset, int pukLength, int pukRetries) =>
        CredentialNative.Create(slot, pin, pinOffset, pinLength, pinRetries, puk, pukOffset,
            pukLength, pukRetries);

    public static bool Verify(int slot, byte[] candidate) =>
        Verify(slot, candidate, 0, candidate.Length);

    public static bool Verify(int slot, byte[] candidate, int offset, int length) =>
        CredentialNative.Verify(slot, candidate, offset, length);

    public static bool IsVerified(int slot) => CredentialNative.IsVerified(slot);

    public static void Change(int slot, byte[] newPin) => Change(slot, newPin, 0, newPin.Length);

    public static void Change(int slot, byte[] newPin, int offset, int length) =>
        CredentialNative.Change(slot, newPin, offset, length);

    public static bool Unblock(int slot, byte[] puk, byte[] newPin) =>
        Unblock(slot, puk, 0, puk.Length, newPin, 0, newPin.Length);

    public static bool Unblock(int slot, byte[] puk, int pukOffset, int pukLength, byte[] newPin,
        int newPinOffset, int newPinLength) =>
        CredentialNative.Unblock(slot, puk, pukOffset, pukLength, newPin, newPinOffset,
            newPinLength);

    public static int RetriesRemaining(int slot) => CredentialNative.RetriesRemaining(slot, 0);

    public static int PukRetriesRemaining(int slot) => CredentialNative.RetriesRemaining(slot, 1);
}
