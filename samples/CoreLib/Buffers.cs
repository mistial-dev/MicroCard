namespace MicroCard.Core;

public static class ByteBuffer
{
    public static bool Contains(int bufferLength, int offset, int length) =>
        bufferLength >= 0 && offset >= 0 && length >= 0 && offset <= bufferLength &&
        length <= bufferLength - offset;

    public static bool Copy(byte[] source, int sourceOffset, byte[] destination,
        int destinationOffset, int length) =>
        MicroCard.Framework.Buffers.Copy(source, sourceOffset, destination, destinationOffset, length);

    public static bool Fill(byte[] destination, int offset, int length, byte value)
    {
        if (!Contains(destination.Length, offset, length))
            return false;
        for (int index = 0; index < length; index++)
            destination[offset + index] = value;
        return true;
    }

    public static bool Clear(byte[] destination, int offset, int length) =>
        Fill(destination, offset, length, 0);

    public static bool Equals(byte[] left, int leftOffset, byte[] right, int rightOffset,
        int length)
    {
        if (!Contains(left.Length, leftOffset, length) ||
            !Contains(right.Length, rightOffset, length))
            return false;
        int difference = 0;
        for (int index = 0; index < length; index++)
            difference |= left[leftOffset + index] ^ right[rightOffset + index];
        return difference == 0;
    }

    public static int Compare(byte[] left, int leftOffset, int leftLength,
        byte[] right, int rightOffset, int rightLength)
    {
        if (!Contains(left.Length, leftOffset, leftLength) ||
            !Contains(right.Length, rightOffset, rightLength))
            return 0;
        int common = Int32Math.Min(leftLength, rightLength);
        for (int index = 0; index < common; index++)
        {
            int leftValue = left[leftOffset + index];
            int rightValue = right[rightOffset + index];
            if (leftValue < rightValue) return -1;
            if (leftValue > rightValue) return 1;
        }
        return Int32Comparison.Compare(leftLength, rightLength);
    }
}

public static class Int32Buffer
{
    public static bool Copy(int[] source, int sourceOffset, int[] destination,
        int destinationOffset, int length)
    {
        if (!ByteBuffer.Contains(source.Length, sourceOffset, length) ||
            !ByteBuffer.Contains(destination.Length, destinationOffset, length))
            return false;
        if (source == destination && destinationOffset > sourceOffset &&
            destinationOffset - sourceOffset < length)
        {
            for (int index = length - 1; index >= 0; index--)
                destination[destinationOffset + index] = source[sourceOffset + index];
        }
        else
        {
            for (int index = 0; index < length; index++)
                destination[destinationOffset + index] = source[sourceOffset + index];
        }
        return true;
    }

    public static bool Fill(int[] destination, int offset, int length, int value)
    {
        if (!ByteBuffer.Contains(destination.Length, offset, length))
            return false;
        for (int index = 0; index < length; index++)
            destination[offset + index] = value;
        return true;
    }

    public static bool Clear(int[] destination, int offset, int length) =>
        Fill(destination, offset, length, 0);
}
