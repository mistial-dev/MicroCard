using System;
using MicroCard.Core;

static void Check(bool value)
{
    if (!value) throw new Exception("core assertion failed");
}

Check(ByteBuffer.Contains(4, 0, 4));
Check(ByteBuffer.Contains(4, 4, 0));
Check(!ByteBuffer.Contains(4, -1, 1));
Check(!ByteBuffer.Contains(4, 1, int.MaxValue));

byte[] rightOverlap = [1, 2, 3, 4, 5];
Check(ByteBuffer.Copy(rightOverlap, 0, rightOverlap, 1, 4));
Check(ByteBuffer.Equals(rightOverlap, 0, new byte[] { 1, 1, 2, 3, 4 }, 0, 5));
byte[] leftOverlap = [1, 2, 3, 4, 5];
Check(ByteBuffer.Copy(leftOverlap, 1, leftOverlap, 0, 4));
Check(ByteBuffer.Equals(leftOverlap, 0, new byte[] { 2, 3, 4, 5, 5 }, 0, 5));
byte[] unchanged = [1, 2, 3];
Check(!ByteBuffer.Copy(unchanged, 0, unchanged, 2, 2));
Check(ByteBuffer.Equals(unchanged, 0, new byte[] { 1, 2, 3 }, 0, 3));
Check(ByteBuffer.Fill(unchanged, 1, 2, 9));
Check(ByteBuffer.Clear(unchanged, 2, 1));
Check(ByteBuffer.Equals(unchanged, 0, new byte[] { 1, 9, 0 }, 0, 3));
Check(!ByteBuffer.Fill(unchanged, 2, 2, 7));
Check(ByteBuffer.Compare(new byte[] { 1, 2 }, 0, 2, new byte[] { 1, 3 }, 0, 2) < 0);
Check(ByteBuffer.Compare(new byte[] { 1 }, 0, 1, new byte[] { 1, 0 }, 0, 2) < 0);
Check(ByteBuffer.Compare(new byte[] { 2 }, 0, 1, new byte[] { 1 }, 0, 1) > 0);

int[] integers = [1, 2, 3, 4];
Check(Int32Buffer.Copy(integers, 0, integers, 1, 3));
Check(integers[0] == 1 && integers[1] == 1 && integers[2] == 2 && integers[3] == 3);
Check(Int32Buffer.Fill(integers, 1, 2, -1));
Check(Int32Buffer.Clear(integers, 2, 2));
Check(integers[0] == 1 && integers[1] == -1 && integers[2] == 0 && integers[3] == 0);

byte[] encoded = new byte[8];
BinaryPrimitives.WriteInt32BigEndian(encoded, 0, unchecked((int)0x89ABCDEF));
BinaryPrimitives.WriteInt32LittleEndian(encoded, 4, unchecked((int)0x89ABCDEF));
Check(BinaryPrimitives.ReadInt32BigEndian(encoded, 0) == unchecked((int)0x89ABCDEF));
Check(BinaryPrimitives.ReadInt32LittleEndian(encoded, 4) == unchecked((int)0x89ABCDEF));
BinaryPrimitives.WriteUInt16BigEndian(encoded, 0, 0xFEDC);
BinaryPrimitives.WriteUInt16LittleEndian(encoded, 2, 0xFEDC);
Check(BinaryPrimitives.ReadUInt16BigEndian(encoded, 0) == 0xFEDC);
Check(BinaryPrimitives.ReadUInt16LittleEndian(encoded, 2) == 0xFEDC);

Check(Int32Math.Min(-1, 2) == -1);
Check(Int32Math.Max(-1, 2) == 2);
Check(Int32Math.Clamp(4, 5, 9) == 5 && Int32Math.Clamp(10, 5, 9) == 9);
Check(Int32Math.Sign(-3) == -1 && Int32Math.Sign(0) == 0 && Int32Math.Sign(3) == 1);
Check(Int32Math.AbsSaturating(int.MinValue) == int.MaxValue);
Check(Int32Math.AddChecked(2, 3) == 5);
Check(Int32Math.SubtractChecked(2, 3) == -1);
Check(Int32Math.MultiplyChecked(-2, 3) == -6);
Check(Int32Comparison.Equals(4, 4) && Int32Comparison.Compare(4, 5) < 0);

Console.WriteLine("PASS: 42 bounded core-library assertions");
