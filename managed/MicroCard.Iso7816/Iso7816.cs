using MicroCard.Framework;
using MicroCard.Internal;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Iso7816;

// ISO/IEC 7816-4:2020, 5.1-5.2: command-response pairs, status words and APDU structure.
public static class StatusWords
{
    public const StatusWord Success = StatusWord.Success;
    public const StatusWord WarningStateUnchanged = StatusWord.WarningStateUnchanged;
    public const StatusWord WarningStateChanged = StatusWord.WarningStateChanged;
    public const StatusWord WrongLength = StatusWord.WrongLength;
    public const StatusWord SecurityStatusNotSatisfied = StatusWord.SecurityStatusNotSatisfied;
    public const StatusWord AuthenticationMethodBlocked = StatusWord.AuthenticationMethodBlocked;
    public const StatusWord ConditionsNotSatisfied = StatusWord.ConditionsNotSatisfied;
    public const StatusWord IncorrectData = StatusWord.IncorrectData;
    public const StatusWord FunctionNotSupported = StatusWord.FunctionNotSupported;
    public const StatusWord FileNotFound = StatusWord.FileNotFound;
    public const StatusWord RecordNotFound = StatusWord.RecordNotFound;
    public const StatusWord NotEnoughMemory = StatusWord.NotEnoughMemory;
    public const StatusWord IncorrectParameters = StatusWord.IncorrectParameters;
    public const StatusWord ReferenceDataNotFound = StatusWord.ReferenceDataNotFound;
    public const StatusWord WrongParameters = StatusWord.WrongParameters;
    public const StatusWord InstructionNotSupported = StatusWord.InstructionNotSupported;
    public const StatusWord ClassNotSupported = StatusWord.ClassNotSupported;
    public const StatusWord UnknownError = StatusWord.UnknownError;
}

public static class Instructions
{
    public const int Select = 0xA4;
    public const int GetData = 0xCA;
    public const int PutData = 0xDA;
    public const int Verify = 0x20;
    public const int ChangeReferenceData = 0x24;
    public const int GetChallenge = 0x84;
    public const int ExternalAuthenticate = 0x82;
    public const int InternalAuthenticate = 0x88;
}

public static class ShortCommand
{
    public const int Case1 = 1;
    public const int Case2 = 2;
    public const int Case3 = 3;
    public const int Case4 = 4;
    public const int NoExpectedLength = -1;
    public const int DataOffsetIndex = 0;
    public const int DataLengthIndex = 1;
    public const int ExpectedLengthIndex = 2;
    public const int CaseIndex = 3;
    public const int ResultSize = 4;

    public static bool TryParse(byte[] command, int offset, int length, int[] result, int resultOffset)
    {
        if (!BufferBounds.Contains(command.Length, offset, length) || length < 4 ||
            !BufferBounds.Contains(result.Length, resultOffset, ResultSize))
            return false;

        int dataOffset = offset + 4;
        int dataLength = 0;
        int expectedLength = NoExpectedLength;
        int commandCase = Case1;

        if (length == 5)
        {
            expectedLength = DecodeExpectedLength(command[offset + 4]);
            commandCase = Case2;
        }
        else if (length > 5)
        {
            int declaredLength = command[offset + 4];
            if (declaredLength == 0)
                return false;

            dataOffset = offset + 5;
            dataLength = declaredLength;
            if (length == 5 + declaredLength)
                commandCase = Case3;
            else if (length == 6 + declaredLength)
            {
                commandCase = Case4;
                expectedLength = DecodeExpectedLength(command[offset + length - 1]);
            }
            else
                return false;
        }

        result[resultOffset + DataOffsetIndex] = dataOffset;
        result[resultOffset + DataLengthIndex] = dataLength;
        result[resultOffset + ExpectedLengthIndex] = expectedLength;
        result[resultOffset + CaseIndex] = commandCase;
        return true;
    }

    private static int DecodeExpectedLength(int encoded) => encoded == 0 ? 256 : encoded;
}

public static class Aid
{
    public const int MinimumLength = 5;
    public const int MaximumLength = 16;

    public static bool IsValid(byte[] value, int offset, int length) =>
        length >= MinimumLength && length <= MaximumLength &&
        BufferBounds.Contains(value.Length, offset, length);

    public static bool Equals(byte[] left, int leftOffset, int leftLength,
        byte[] right, int rightOffset, int rightLength)
    {
        if (leftLength != rightLength || !IsValid(left, leftOffset, leftLength) ||
            !IsValid(right, rightOffset, rightLength))
            return false;

        int difference = 0;
        for (int index = 0; index < leftLength; index++)
            difference |= left[leftOffset + index] ^ right[rightOffset + index];
        return difference == 0;
    }
}

public static class CommandRouting
{
    public const int Any = -1;

    public static bool Matches(byte[] command, int offset, int length,
        int classValue, int classMask, int instruction, int parameter1, int parameter2)
    {
        if (!BufferBounds.Contains(command.Length, offset, length) || length < 4 ||
            classValue < 0 || classValue > 255 || classMask < 0 || classMask > 255 ||
            instruction < 0 || instruction > 255)
            return false;

        return (command[offset] & classMask) == (classValue & classMask) &&
            command[offset + 1] == instruction &&
            MatchesOptional(command[offset + 2], parameter1) &&
            MatchesOptional(command[offset + 3], parameter2);
    }

    private static bool MatchesOptional(int actual, int expected) =>
        expected == Any || expected >= 0 && expected <= 255 && actual == expected;
}

public static class BerTlv
{
    public const int TagIndex = BoundedTlv.TagIndex;
    public const int HeaderLengthIndex = BoundedTlv.HeaderLengthIndex;
    public const int ValueOffsetIndex = BoundedTlv.ValueOffsetIndex;
    public const int ValueLengthIndex = BoundedTlv.ValueLengthIndex;
    public const int NextOffsetIndex = BoundedTlv.NextOffsetIndex;
    public const int ResultSize = BoundedTlv.ResultSize;

    public static bool TryRead(byte[] input, int offset, int length, int[] result, int resultOffset) =>
        BoundedTlv.TryRead(input, offset, length, result, resultOffset, false);

    public static int WriteHeader(byte[] output, int offset, int capacity, int tag, int valueLength) =>
        BoundedTlv.WriteHeader(output, offset, capacity, tag, valueLength);

    public static int Write(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength) =>
        BoundedTlv.Write(output, offset, capacity, tag, value, valueOffset, valueLength);
}

internal static class BufferBounds
{
    public static bool Contains(int bufferLength, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= bufferLength && length <= bufferLength - offset;
}
