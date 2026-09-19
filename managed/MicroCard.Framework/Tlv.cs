namespace MicroCard.Framework;

// Desktop reference for the bounded native TLV service.
public static class Tlv
{
    private const int ResultSize = 5;
    private const int TagIndex = 0, HeaderLengthIndex = 1, ValueOffsetIndex = 2,
        ValueLengthIndex = 3, NextOffsetIndex = 4;
    private const int BooleanTag = 1, IntegerTag = 2, BitStringTag = 3, NullTag = 5,
        ObjectIdentifierTag = 6;
    private static bool Contains(int size, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= size && length <= size - offset;
    private static int FirstTagByte(int tag, int length) =>
        length == 3 ? tag >> 16 : length == 2 ? tag >> 8 : tag;
    public static bool TryRead(byte[] input, int offset, int length, int[] result, int resultOffset, bool der)
    {
        if (!Contains(input.Length, offset, length) || length < 2 ||
            !Contains(result.Length, resultOffset, ResultSize))
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

        if (valueLength > end - cursor ||
            der && (!CanonicalTagForm(tag) || !CanonicalValue(input, cursor, valueLength, tag)))
            return false;

        result[resultOffset + TagIndex] = tag;
        result[resultOffset + HeaderLengthIndex] = cursor - offset;
        result[resultOffset + ValueOffsetIndex] = cursor;
        result[resultOffset + ValueLengthIndex] = valueLength;
        result[resultOffset + NextOffsetIndex] = cursor + valueLength;
        return true;
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
            return (first & 0x1F) == 0x1F && (last & 0x80) == 0 &&
                (last & 0x7F) >= 0x1F ? 2 : -1;
        }
        int middle = tag >> 8 & 0xFF;
        int finalByte = tag & 0xFF;
        return ((tag >> 16) & 0x1F) == 0x1F && (middle & 0x80) != 0 &&
            (middle & 0x7F) != 0 && (finalByte & 0x80) == 0 ? 3 : -1;
    }

    private static bool CanonicalTagForm(int tag)
    {
        int length = EncodedTagLength(tag);
        if (length < 0)
            return false;
        int first = FirstTagByte(tag, length);
        if ((first & 0xC0) != 0 || length != 1)
            return true;
        int number = first & 0x1F;
        if (number == 0)
            return false;
        if (number is >= 1 and <= 6)
            return (first & 0x20) == 0;
        if (number is 16 or 17)
            return (first & 0x20) != 0;
        return true;
    }

    private static bool CanonicalValue(byte[] input, int offset, int length, int tag)
    {
        if (tag == BooleanTag)
            return length == 1 && (input[offset] == 0 || input[offset] == 0xFF);
        if (tag == IntegerTag)
            return CanonicalInteger(input, offset, length);
        if (tag == BitStringTag)
            return CanonicalBitString(input, offset, length);
        if (tag == NullTag)
            return length == 0;
        if (tag == ObjectIdentifierTag)
            return CanonicalObjectIdentifier(input, offset, length);
        return true;
    }

    private static bool CanonicalInteger(byte[] input, int offset, int length)
    {
        if (length < 1)
            return false;
        if (length == 1)
            return true;
        int first = input[offset];
        int second = input[offset + 1];
        return !(first == 0 && (second & 0x80) == 0 || first == 0xFF && (second & 0x80) != 0);
    }

    private static bool CanonicalBitString(byte[] input, int offset, int length)
    {
        if (length < 1)
            return false;
        int unused = input[offset];
        if (unused < 0 || unused > 7 || length == 1 && unused != 0)
            return false;
        return unused == 0 || (input[offset + length - 1] & ((1 << unused) - 1)) == 0;
    }

    private static bool CanonicalObjectIdentifier(byte[] input, int offset, int length)
    {
        if (length < 1)
            return false;
        bool firstGroup = true;
        for (int index = 0; index < length; index++)
        {
            int value = input[offset + index];
            if (firstGroup && value == 0x80)
                return false;
            firstGroup = (value & 0x80) == 0;
        }
        return firstGroup;
    }
}
