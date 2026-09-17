using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Cryptography;

// GlobalPlatform SCP03 v1.1.2, 4.1.5: 12-byte label, 00, L, counter, context.
public static class Kdf108
{
    public static byte[] DeriveScp03(KeyHandle key, int keyPurpose, byte[] context, int outputBytes)
    {
        if (keyPurpose < 0 || keyPurpose > 255 || context.Length > 239 ||
            outputBytes is not (8 or 16 or 24 or 32))
            return new byte[0];

        var fixedInput = new byte[16 + context.Length];
        fixedInput[11] = (byte)keyPurpose;
        int outputBits = outputBytes * 8;
        fixedInput[13] = (byte)(outputBits >> 8);
        fixedInput[14] = (byte)outputBits;
        for (int index = 0; index < context.Length; index++)
            fixedInput[16 + index] = context[index];

        var output = new byte[outputBytes];
        int written = 0;
        for (int counter = 1; written < outputBytes; counter++)
        {
            fixedInput[15] = (byte)counter;
            var block = key.AesCmac(fixedInput);
            for (int index = 0; index < block.Length && written < outputBytes; index++)
                output[written++] = block[index];
        }
        return output;
    }
}
