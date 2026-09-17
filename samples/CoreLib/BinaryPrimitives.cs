namespace MicroCard.Core;

public static class BinaryPrimitives
{
    public static int ReadInt32BigEndian(byte[] source, int offset) =>
        source[offset] << 24 | source[offset + 1] << 16 |
        source[offset + 2] << 8 | source[offset + 3];

    public static int ReadInt32LittleEndian(byte[] source, int offset) =>
        source[offset] | source[offset + 1] << 8 |
        source[offset + 2] << 16 | source[offset + 3] << 24;

    public static void WriteInt32BigEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)(value >> 24);
        destination[offset + 1] = (byte)(value >> 16);
        destination[offset + 2] = (byte)(value >> 8);
        destination[offset + 3] = (byte)value;
    }

    public static void WriteInt32LittleEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
    }

    public static int ReadUInt16BigEndian(byte[] source, int offset) =>
        source[offset] << 8 | source[offset + 1];

    public static int ReadUInt16LittleEndian(byte[] source, int offset) =>
        source[offset] | source[offset + 1] << 8;

    public static void WriteUInt16BigEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)(value >> 8);
        destination[offset + 1] = (byte)value;
    }

    public static void WriteUInt16LittleEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
    }
}
