using MicroCard.Framework;
using MicroCard.Internal;

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

    public const int TagIndex = BoundedTlv.TagIndex;
    public const int HeaderLengthIndex = BoundedTlv.HeaderLengthIndex;
    public const int ValueOffsetIndex = BoundedTlv.ValueOffsetIndex;
    public const int ValueLengthIndex = BoundedTlv.ValueLengthIndex;
    public const int NextOffsetIndex = BoundedTlv.NextOffsetIndex;
    public const int ResultSize = BoundedTlv.ResultSize;

    public static bool TryRead(byte[] input, int offset, int length, int[] result, int resultOffset) =>
        BoundedTlv.TryRead(input, offset, length, result, resultOffset, true);

    public static int WriteInteger(byte[] output, int offset, int capacity, int value)
    {
        int length = value is >= -128 and <= 127 ? 1 :
            value is >= -32768 and <= 32767 ? 2 :
            value is >= -8388608 and <= 8388607 ? 3 : 4;
        int header = BoundedTlv.HeaderLength(IntegerTag, length);
        if (!BoundedTlv.Contains(output.Length, offset, capacity) || header + length > capacity)
            return -1;
        BoundedTlv.WriteHeader(output, offset, capacity, IntegerTag, length);
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
        if (!BoundedTlv.Contains(value.Length, valueOffset, valueLength) ||
            unusedBits < 0 || unusedBits > 7 || valueLength == 0 && unusedBits != 0 ||
            valueLength > 0 && unusedBits > 0 &&
            (value[valueOffset + valueLength - 1] & ((1 << unusedBits) - 1)) != 0)
            return -1;
        int contentLength = valueLength + 1;
        int header = BoundedTlv.HeaderLength(BitStringTag, contentLength);
        if (!BoundedTlv.Contains(output.Length, offset, capacity) || header + contentLength > capacity)
            return -1;
        int destination = offset + header + 1;
        if (!Buffers.Copy(value, valueOffset, output, destination, valueLength))
            return -1;
        BoundedTlv.WriteHeader(output, offset, capacity, BitStringTag, contentLength);
        output[offset + header] = (byte)unusedBits;
        return header + contentLength;
    }

    public static int WriteObjectIdentifier(byte[] output, int offset, int capacity,
        byte[] encodedValue, int valueOffset, int valueLength)
    {
        if (!BoundedTlv.IsCanonicalObjectIdentifier(encodedValue, valueOffset, valueLength))
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
        int tagLength = BoundedTlv.EncodedTagLength(tag);
        if (tagLength < 0 || (BoundedTlv.FirstTagByte(tag, tagLength) & 0xE0) == 0 ||
            (BoundedTlv.FirstTagByte(tag, tagLength) & 0x20) != 0)
            return -1;
        return WriteValue(output, offset, capacity, tag, value, valueOffset, valueLength);
    }

    public static int WriteTaggedConstructed(byte[] output, int offset, int capacity, int tag,
        byte[] encodedValues, int valueOffset, int valueLength,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        int tagLength = BoundedTlv.EncodedTagLength(tag);
        if (tagLength < 0 || (BoundedTlv.FirstTagByte(tag, tagLength) & 0xC0) == 0 ||
            (BoundedTlv.FirstTagByte(tag, tagLength) & 0x20) == 0 ||
            !TryValidate(encodedValues, valueOffset, valueLength, scratch, scratchOffset, scratchLength))
            return -1;
        return WriteValue(output, offset, capacity, tag, encodedValues, valueOffset, valueLength);
    }

    public static bool TryValidate(byte[] input, int offset, int length,
        int[] scratch, int scratchOffset, int scratchLength)
    {
        if (!BoundedTlv.Contains(input.Length, offset, length) ||
            !BoundedTlv.Contains(scratch.Length, scratchOffset, scratchLength) ||
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
            if (BoundedTlv.IsConstructed(tag) && valueLength > 0)
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
        if (!BoundedTlv.IsCanonicalPrimitiveSequence(encodedValues, valueOffset, valueLength))
            return -1;
        return WriteValue(output, offset, capacity, tag, encodedValues, valueOffset, valueLength);
    }

    private static int WriteValue(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength)
    {
        return BoundedTlv.Write(output, offset, capacity, tag, value, valueOffset, valueLength);
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

}
