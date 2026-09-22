namespace MicroCard.Internal;

internal static class DerCanonical
{
    internal static bool IsObjectIdentifier(byte[] input, int offset, int length)
    {
        if (!BoundedTlv.Contains(input.Length, offset, length) || length < 1)
            return false;
        bool firstGroupByte = true;
        for (int index = 0; index < length; index++)
        {
            int value = input[offset + index];
            if (firstGroupByte && value == 0x80)
                return false;
            firstGroupByte = (value & 0x80) == 0;
        }
        return firstGroupByte;
    }

    internal static bool IsPrimitiveSequence(byte[] input, int offset, int length)
    {
        if (!BoundedTlv.Contains(input.Length, offset, length))
            return false;
        int end = offset + length;
        int cursor = offset;
        while (cursor < end)
        {
            if (end - cursor < 2)
                return false;
            int tag = input[cursor];
            if (tag == 0 || (tag & 0x1F) == 0x1F)
                return false;
            int valueLength = ReadLength(input, cursor + 1, end);
            if (valueLength < 0)
                return false;
            int valueOffset = cursor + 1 + LengthOctets(input[cursor + 1]);
            if (valueLength > end - valueOffset ||
                !IsValue(input, valueOffset, valueLength, tag) ||
                (tag & 0x20) != 0)
                return false;
            cursor = valueOffset + valueLength;
        }
        return cursor == end;
    }

    private static int ReadLength(byte[] input, int offset, int end)
    {
        if (offset >= end)
            return -1;
        int first = input[offset];
        if (first < 0x80)
            return first;
        if (first == 0x81 && offset + 1 < end && input[offset + 1] >= 0x80)
            return input[offset + 1];
        if (first == 0x82 && offset + 2 < end)
        {
            int value = (input[offset + 1] << 8) | input[offset + 2];
            return value >= 0x100 ? value : -1;
        }
        return -1;
    }

    private static int LengthOctets(int first) => first < 0x80 ? 1 : first == 0x81 ? 2 : 3;

    private static bool IsValue(byte[] input, int offset, int length, int tag)
    {
        if (tag == 1)
            return length == 1 && (input[offset] == 0 || input[offset] == 0xFF);
        if (tag == 2)
            return IsInteger(input, offset, length);
        if (tag == 3)
            return IsBitString(input, offset, length);
        if (tag == 5)
            return length == 0;
        if (tag == 6)
            return IsObjectIdentifier(input, offset, length);
        return true;
    }

    private static bool IsInteger(byte[] input, int offset, int length)
    {
        if (length < 1)
            return false;
        if (length == 1)
            return true;
        int first = input[offset];
        int second = input[offset + 1];
        return !(first == 0 && (second & 0x80) == 0 ||
            first == 0xFF && (second & 0x80) != 0);
    }

    private static bool IsBitString(byte[] input, int offset, int length)
    {
        if (length < 1)
            return false;
        int unused = input[offset];
        if (unused < 0 || unused > 7 || length == 1 && unused != 0)
            return false;
        return unused == 0 || (input[offset + length - 1] & ((1 << unused) - 1)) == 0;
    }
}
