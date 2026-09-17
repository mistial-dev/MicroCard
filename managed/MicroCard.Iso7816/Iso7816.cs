using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Iso7816;

// ISO/IEC 7816-4:2020, 5.1-5.2: command-response pairs, status words and APDU structure.
public static class StatusWords
{
    public const int Success = 0x9000;
    public const int WarningStateUnchanged = 0x6200;
    public const int WarningStateChanged = 0x6300;
    public const int WrongLength = 0x6700;
    public const int SecurityStatusNotSatisfied = 0x6982;
    public const int AuthenticationMethodBlocked = 0x6983;
    public const int ConditionsNotSatisfied = 0x6985;
    public const int IncorrectData = 0x6A80;
    public const int FunctionNotSupported = 0x6A81;
    public const int FileNotFound = 0x6A82;
    public const int RecordNotFound = 0x6A83;
    public const int NotEnoughMemory = 0x6A84;
    public const int IncorrectParameters = 0x6A86;
    public const int ReferenceDataNotFound = 0x6A88;
    public const int WrongParameters = 0x6B00;
    public const int InstructionNotSupported = 0x6D00;
    public const int ClassNotSupported = 0x6E00;
    public const int UnknownError = 0x6F00;
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
    public const int TagIndex = 0;
    public const int HeaderLengthIndex = 1;
    public const int ValueOffsetIndex = 2;
    public const int ValueLengthIndex = 3;
    public const int NextOffsetIndex = 4;
    public const int ResultSize = 5;

    public static bool TryRead(byte[] input, int offset, int length, int[] result, int resultOffset)
    {
        if (!BufferBounds.Contains(input.Length, offset, length) || length < 2 ||
            !BufferBounds.Contains(result.Length, resultOffset, ResultSize))
            return false;

        int end = offset + length;
        int cursor = offset;
        int tag = input[cursor++];
        if (tag == 0)
            return false;
        if ((tag & 0x1F) == 0x1F)
        {
            if (cursor >= end)
                return false;
            int next = input[cursor++];
            if ((next & 0x7F) == 0)
                return false;
            tag = (tag << 8) | next;
            if ((next & 0x80) != 0)
            {
                if (cursor >= end)
                    return false;
                next = input[cursor++];
                if ((next & 0x80) != 0)
                    return false;
                tag = (tag << 8) | next;
            }
            else if ((next & 0x7F) < 0x1F)
                return false;
        }

        if (cursor >= end)
            return false;
        int firstLength = input[cursor++];
        int valueLength;
        if (firstLength < 0x80)
            valueLength = firstLength;
        else if (firstLength == 0x81)
        {
            if (cursor >= end)
                return false;
            valueLength = input[cursor++];
            if (valueLength < 0x80)
                return false;
        }
        else if (firstLength == 0x82)
        {
            if (cursor + 1 >= end)
                return false;
            valueLength = (input[cursor] << 8) | input[cursor + 1];
            cursor += 2;
            if (valueLength < 0x100)
                return false;
        }
        else
            return false;

        if (valueLength > end - cursor)
            return false;

        result[resultOffset + TagIndex] = tag;
        result[resultOffset + HeaderLengthIndex] = cursor - offset;
        result[resultOffset + ValueOffsetIndex] = cursor;
        result[resultOffset + ValueLengthIndex] = valueLength;
        result[resultOffset + NextOffsetIndex] = cursor + valueLength;
        return true;
    }

    public static int WriteHeader(byte[] output, int offset, int capacity, int tag, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        int lengthLength = EncodedLengthLength(valueLength);
        if (tagLength < 0 || lengthLength < 0 || !BufferBounds.Contains(output.Length, offset, capacity) ||
            tagLength + lengthLength > capacity)
            return -1;

        int cursor = offset;
        if (tagLength == 3)
            output[cursor++] = (byte)(tag >> 16);
        if (tagLength >= 2)
            output[cursor++] = (byte)(tag >> 8);
        output[cursor++] = (byte)tag;

        if (lengthLength == 1)
            output[cursor++] = (byte)valueLength;
        else if (lengthLength == 2)
        {
            output[cursor++] = 0x81;
            output[cursor++] = (byte)valueLength;
        }
        else
        {
            output[cursor++] = 0x82;
            output[cursor++] = (byte)(valueLength >> 8);
            output[cursor++] = (byte)valueLength;
        }
        return cursor - offset;
    }

    public static int Write(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        int lengthLength = EncodedLengthLength(valueLength);
        if (!BufferBounds.Contains(value.Length, valueOffset, valueLength) ||
            !BufferBounds.Contains(output.Length, offset, capacity) || tagLength < 0 || lengthLength < 0 ||
            tagLength + lengthLength > capacity - valueLength)
            return -1;
        int headerLength = tagLength + lengthLength;
        int destination = offset + headerLength;
        if (output == value)
        {
            if (destination > valueOffset && destination < valueOffset + valueLength)
                for (int index = valueLength - 1; index >= 0; index--)
                    output[destination + index] = value[valueOffset + index];
            else
                for (int index = 0; index < valueLength; index++)
                    output[destination + index] = value[valueOffset + index];
            WriteHeader(output, offset, capacity, tag, valueLength);
        }
        else
        {
            WriteHeader(output, offset, capacity, tag, valueLength);
            for (int index = 0; index < valueLength; index++)
                output[destination + index] = value[valueOffset + index];
        }
        return headerLength + valueLength;
    }

    private static int EncodedTagLength(int tag)
    {
        if (tag <= 0 || tag > 0xFFFFFF)
            return -1;
        if (tag <= 0xFF)
            return (tag & 0x1F) == 0x1F ? -1 : 1;
        if (tag <= 0xFFFF)
        {
            int first = tag >> 8;
            int last = tag & 0xFF;
            return (first & 0x1F) == 0x1F && (last & 0x80) == 0 && (last & 0x7F) >= 0x1F ? 2 : -1;
        }
        int middle = (tag >> 8) & 0xFF;
        int finalByte = tag & 0xFF;
        return ((tag >> 16) & 0x1F) == 0x1F && (middle & 0x80) != 0 &&
            (middle & 0x7F) != 0 && (finalByte & 0x80) == 0 ? 3 : -1;
    }

    private static int EncodedLengthLength(int valueLength)
    {
        if (valueLength < 0 || valueLength > 0xFFFF)
            return -1;
        if (valueLength < 0x80)
            return 1;
        return valueLength < 0x100 ? 2 : 3;
    }
}

internal static class BufferBounds
{
    public static bool Contains(int bufferLength, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= bufferLength && length <= bufferLength - offset;
}
