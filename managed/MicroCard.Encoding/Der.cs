using MicroCard.Framework;

[assembly: DependencyExport(DependencyAccess.Any)]

namespace MicroCard.Encoding;

// ITU-T X.690 (02/2021), 8.1 and 11: identifier, definite length, and DER canonical forms.
public static class Der
{
    // Multi-octet identifiers are packed big-endian, for example 0x9F1F.
    public const int BooleanTag = 0x01;
    public const int IntegerTag = 0x02;
    public const int BitStringTag = 0x03;
    public const int OctetStringTag = 0x04;
    public const int NullTag = 0x05;
    public const int ObjectIdentifierTag = 0x06;
    public const int SequenceTag = 0x30;
    public const int SetTag = 0x31;

    public const int TagIndex = 0;
    public const int HeaderLengthIndex = 1;
    public const int ValueOffsetIndex = 2;
    public const int ValueLengthIndex = 3;
    public const int NextOffsetIndex = 4;
    public const int ResultSize = 5;

    public static bool TryRead(byte[] input, int offset, int length, int[] result, int resultOffset)
    {
        if (!Bounds.Contains(input.Length, offset, length) || length < 2 ||
            !Bounds.Contains(result.Length, resultOffset, ResultSize))
            return false;

        int end = offset + length;
        int tagLength = ReadTagLength(input, offset, end);
        if (tagLength < 0)
            return false;
        int tag = DecodeTag(input, offset, tagLength);
        if (!CanonicalTagForm(tag))
            return false;
        int cursor = offset + tagLength;
        int valueLength = ReadLength(input, cursor, end);
        if (valueLength < 0)
            return false;
        cursor += LengthOctets(input[cursor]);
        if (valueLength > end - cursor || !CanonicalValue(input, cursor, valueLength, tag))
            return false;

        result[resultOffset + TagIndex] = tag;
        result[resultOffset + HeaderLengthIndex] = cursor - offset;
        result[resultOffset + ValueOffsetIndex] = cursor;
        result[resultOffset + ValueLengthIndex] = valueLength;
        result[resultOffset + NextOffsetIndex] = cursor + valueLength;
        return true;
    }

    public static int WriteInteger(byte[] output, int offset, int capacity, int value)
    {
        int length = value is >= -128 and <= 127 ? 1 :
            value is >= -32768 and <= 32767 ? 2 :
            value is >= -8388608 and <= 8388607 ? 3 : 4;
        int header = HeaderLength(IntegerTag, length);
        if (!Bounds.Contains(output.Length, offset, capacity) || header + length > capacity)
            return -1;
        WriteHeader(output, offset, IntegerTag, length);
        int destination = offset + header;
        int remaining = value;
        for (int index = length - 1; index >= 0; index--)
        {
            output[destination + index] = (byte)remaining;
            remaining >>= 8;
        }
        return header + length;
    }

    public static int WriteOctetString(byte[] output, int offset, int capacity,
        byte[] value, int valueOffset, int valueLength) =>
        WriteValue(output, offset, capacity, OctetStringTag, value, valueOffset, valueLength);

    public static int WriteBitString(byte[] output, int offset, int capacity, int unusedBits,
        byte[] value, int valueOffset, int valueLength)
    {
        if (!Bounds.Contains(value.Length, valueOffset, valueLength) ||
            unusedBits < 0 || unusedBits > 7 || valueLength == 0 && unusedBits != 0 ||
            valueLength > 0 && unusedBits > 0 &&
            (value[valueOffset + valueLength - 1] & ((1 << unusedBits) - 1)) != 0)
            return -1;
        int contentLength = valueLength + 1;
        int header = HeaderLength(BitStringTag, contentLength);
        if (!Bounds.Contains(output.Length, offset, capacity) || header + contentLength > capacity)
            return -1;
        int destination = offset + header + 1;
        if (!Copy(output, destination, value, valueOffset, valueLength))
            return -1;
        WriteHeader(output, offset, BitStringTag, contentLength);
        output[offset + header] = (byte)unusedBits;
        return header + contentLength;
    }

    public static int WriteObjectIdentifier(byte[] output, int offset, int capacity,
        byte[] encodedValue, int valueOffset, int valueLength)
    {
        if (!Bounds.Contains(encodedValue.Length, valueOffset, valueLength) ||
            !CanonicalObjectIdentifier(encodedValue, valueOffset, valueLength))
            return -1;
        return WriteValue(output, offset, capacity, ObjectIdentifierTag,
            encodedValue, valueOffset, valueLength);
    }

    public static int WriteSequence(byte[] output, int offset, int capacity,
        byte[] encodedValues, int valueOffset, int valueLength) =>
        WriteConstructed(output, offset, capacity, SequenceTag, encodedValues, valueOffset, valueLength);

    public static int WriteSequence(byte[] output, int offset, int capacity,
        byte[] encodedValues, int valueOffset, int valueLength,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        if (!TryValidate(encodedValues, valueOffset, valueLength, scratch, scratchOffset, scratchLength))
            return -1;
        return WriteValue(output, offset, capacity, SequenceTag, encodedValues, valueOffset, valueLength);
    }

    public static int WriteSetOf(byte[] output, int offset, int capacity,
        byte[] encodedValues, int valueOffset, int valueLength,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        if (!TryValidate(encodedValues, valueOffset, valueLength, scratch, scratchOffset, scratchLength) ||
            !CanonicalSetOfOrder(encodedValues, valueOffset, valueLength, scratch, scratchOffset))
            return -1;
        return WriteValue(output, offset, capacity, SetTag, encodedValues, valueOffset, valueLength);
    }

    public static int WriteTaggedPrimitive(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        if (tagLength < 0 || (FirstTagByte(tag, tagLength) & 0xE0) == 0 ||
            (FirstTagByte(tag, tagLength) & 0x20) != 0)
            return -1;
        return WriteValue(output, offset, capacity, tag, value, valueOffset, valueLength);
    }

    public static int WriteTaggedConstructed(byte[] output, int offset, int capacity, int tag,
        byte[] encodedValues, int valueOffset, int valueLength,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        int tagLength = EncodedTagLength(tag);
        if (tagLength < 0 || (FirstTagByte(tag, tagLength) & 0xC0) == 0 ||
            (FirstTagByte(tag, tagLength) & 0x20) == 0 ||
            !TryValidate(encodedValues, valueOffset, valueLength, scratch, scratchOffset, scratchLength))
            return -1;
        return WriteValue(output, offset, capacity, tag, encodedValues, valueOffset, valueLength);
    }

    public static bool TryValidate(byte[] input, int offset, int length,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        if (!Bounds.Contains(input.Length, offset, length) ||
            !Bounds.Contains(scratch.Length, scratchOffset, scratchLength) ||
            scratchLength < ResultSize + 1)
            return false;
        int stackOffset = scratchOffset + ResultSize;
        int stackLength = scratchLength - ResultSize;
        int depth = 0;
        int cursor = offset;
        int end = offset + length;
        while (true)
        {
            if (cursor == end)
            {
                if (depth == 0)
                    return true;
                depth--;
                end = scratch[stackOffset + depth];
                continue;
            }
            if (cursor > end || !TryRead(input, cursor, end - cursor, scratch, scratchOffset))
                return false;
            int next = scratch[scratchOffset + NextOffsetIndex];
            int tag = scratch[scratchOffset + TagIndex];
            int valueOffset = scratch[scratchOffset + ValueOffsetIndex];
            int valueLength = scratch[scratchOffset + ValueLengthIndex];
            if (ConstructedTag(tag) && valueLength > 0)
            {
                if (depth >= stackLength)
                    return false;
                scratch[stackOffset + depth] = end;
                depth++;
                cursor = valueOffset;
                end = next;
            }
            else
                cursor = next;
        }
    }

    private static int WriteConstructed(byte[] output, int offset, int capacity, int tag,
        byte[] encodedValues, int valueOffset, int valueLength)
    {
        if (!Bounds.Contains(encodedValues.Length, valueOffset, valueLength) ||
            !CanonicalValues(encodedValues, valueOffset, valueLength))
            return -1;
        return WriteValue(output, offset, capacity, tag, encodedValues, valueOffset, valueLength);
    }

    private static int WriteValue(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength)
    {
        int header = HeaderLength(tag, valueLength);
        if (header < 0 || !Bounds.Contains(value.Length, valueOffset, valueLength) ||
            !Bounds.Contains(output.Length, offset, capacity) || header + valueLength > capacity)
            return -1;
        int destination = offset + header;
        if (!Copy(output, destination, value, valueOffset, valueLength))
            return -1;
        WriteHeader(output, offset, tag, valueLength);
        return header + valueLength;
    }

    private static bool Copy(byte[] output, int destination, byte[] value, int source, int length) =>
        MicroCard.Framework.Buffers.Copy(value, source, output, destination, length);

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

    private static int HeaderLength(int tag, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        if (tagLength < 0 || valueLength < 0 || valueLength > 0xFFFF)
            return -1;
        return tagLength + (valueLength < 0x80 ? 1 : valueLength < 0x100 ? 2 : 3);
    }

    private static void WriteHeader(byte[] output, int offset, int tag, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        int cursor = offset;
        if (tagLength == 3)
            output[cursor++] = (byte)(tag >> 16);
        if (tagLength >= 2)
            output[cursor++] = (byte)(tag >> 8);
        output[cursor++] = (byte)tag;
        if (valueLength < 0x80)
            output[cursor] = (byte)valueLength;
        else if (valueLength < 0x100)
        {
            output[cursor] = 0x81;
            output[cursor + 1] = (byte)valueLength;
        }
        else
        {
            output[cursor] = 0x82;
            output[cursor + 1] = (byte)(valueLength >> 8);
            output[cursor + 2] = (byte)valueLength;
        }
    }

    private static int ReadTagLength(byte[] input, int offset, int end)
    {
        if (offset >= end || input[offset] == 0)
            return -1;
        int first = input[offset];
        if ((first & 0x1F) != 0x1F)
            return 1;
        if (offset + 1 >= end)
            return -1;
        int second = input[offset + 1];
        if ((second & 0x7F) == 0)
            return -1;
        if ((second & 0x80) == 0)
            return (second & 0x7F) >= 0x1F ? 2 : -1;
        if (offset + 2 >= end || (input[offset + 2] & 0x80) != 0)
            return -1;
        return 3;
    }

    private static int DecodeTag(byte[] input, int offset, int length)
    {
        int tag = input[offset];
        for (int index = 1; index < length; index++)
            tag = tag << 8 | input[offset + index];
        return tag;
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

    private static int FirstTagByte(int tag, int length) =>
        length == 3 ? tag >> 16 : length == 2 ? tag >> 8 : tag;

    private static bool ConstructedTag(int tag)
    {
        int length = EncodedTagLength(tag);
        return length > 0 && (FirstTagByte(tag, length) & 0x20) != 0;
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

    private static bool CanonicalSetOfOrder(byte[] input, int offset, int length,
        int[] scratch, int scratchOffset)
    {
        int end = offset + length;
        int cursor = offset;
        int previousOffset = -1;
        int previousLength = 0;
        while (cursor < end)
        {
            if (!TryRead(input, cursor, end - cursor, scratch, scratchOffset))
                return false;
            int next = scratch[scratchOffset + NextOffsetIndex];
            int currentLength = next - cursor;
            if (previousOffset >= 0 &&
                CompareEncoded(input, previousOffset, previousLength, cursor, currentLength) > 0)
                return false;
            previousOffset = cursor;
            previousLength = currentLength;
            cursor = next;
        }
        return cursor == end;
    }

    private static int CompareEncoded(byte[] input, int leftOffset, int leftLength,
        int rightOffset, int rightLength)
    {
        int common = leftLength < rightLength ? leftLength : rightLength;
        for (int index = 0; index < common; index++)
        {
            int difference = input[leftOffset + index] - input[rightOffset + index];
            if (difference != 0)
                return difference;
        }
        return leftLength - rightLength;
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

    private static bool CanonicalValues(byte[] input, int offset, int length)
    {
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
                !CanonicalValue(input, valueOffset, valueLength, tag))
                return false;
            if ((tag & 0x20) != 0)
                return false;
            cursor = valueOffset + valueLength;
        }
        return cursor == end;
    }
}

internal static class Bounds
{
    public static bool Contains(int bufferLength, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= bufferLength && length <= bufferLength - offset;
}
