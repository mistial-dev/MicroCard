using MicroCard.Framework;

namespace MicroCard.Internal;

// Shared source keeps the encoding packages independent while giving both facades
// the same bounded tag, length, header, and overlap-safe copy behavior.
internal static class BoundedTlv
{
    internal const int TagIndex = 0;
    internal const int HeaderLengthIndex = 1;
    internal const int ValueOffsetIndex = 2;
    internal const int ValueLengthIndex = 3;
    internal const int NextOffsetIndex = 4;
    internal const int ResultSize = 5;

    internal static bool TryRead(byte[] input, int offset, int length,
        int[] result, int resultOffset, bool der) =>
        Tlv.TryRead(input, offset, length, result, resultOffset, der);

    internal static bool Contains(int size, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= size && length <= size - offset;

    internal static int EncodedTagLength(int tag)
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

    internal static int FirstTagByte(int tag, int length) =>
        length == 3 ? tag >> 16 : length == 2 ? tag >> 8 : tag;

    internal static bool IsConstructed(int tag)
    {
        int length = EncodedTagLength(tag);
        return length > 0 && (FirstTagByte(tag, length) & 0x20) != 0;
    }

    internal static int EncodedLengthLength(int valueLength)
    {
        if (valueLength < 0 || valueLength > 0xFFFF)
            return -1;
        return valueLength < 0x80 ? 1 : valueLength < 0x100 ? 2 : 3;
    }

    internal static int HeaderLength(int tag, int valueLength)
    {
        int tagLength = EncodedTagLength(tag);
        int lengthLength = EncodedLengthLength(valueLength);
        return tagLength < 0 || lengthLength < 0 ? -1 : tagLength + lengthLength;
    }

    internal static int WriteHeader(byte[] output, int offset, int capacity,
        int tag, int valueLength)
    {
        int headerLength = HeaderLength(tag, valueLength);
        if (headerLength < 0 || !Contains(output.Length, offset, capacity) ||
            headerLength > capacity)
            return -1;
        WriteHeaderUnchecked(output, offset, tag, valueLength);
        return headerLength;
    }

    internal static int Write(byte[] output, int offset, int capacity, int tag,
        byte[] value, int valueOffset, int valueLength)
    {
        int headerLength = HeaderLength(tag, valueLength);
        if (headerLength < 0 || !Contains(value.Length, valueOffset, valueLength) ||
            !Contains(output.Length, offset, capacity) ||
            headerLength > capacity - valueLength)
            return -1;
        int destination = offset + headerLength;
        if (!Buffers.Copy(value, valueOffset, output, destination, valueLength))
            return -1;
        WriteHeaderUnchecked(output, offset, tag, valueLength);
        return headerLength + valueLength;
    }

    private static void WriteHeaderUnchecked(byte[] output, int offset, int tag, int valueLength)
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
}
