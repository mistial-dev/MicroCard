using System;
using MicroCard.Encoding;

namespace MicroCard.Encoding.Tests;

static class Program
{
    private static int assertions;

    private static void Check(bool condition)
    {
        assertions++;
        if (!condition) throw new Exception($"DER assertion {assertions} failed");
    }

    private static bool Read(byte[] value)
    {
        int[] result = new int[Der.ResultSize];
        return Der.TryRead(value, 0, value.Length, result, 0) &&
            result[Der.NextOffsetIndex] == value.Length;
    }

    public static void Main()
    {
        Check(Read([0x01, 0x01, 0x00]));
        Check(Read([0x01, 0x01, 0xFF]));
        Check(!Read([0x01, 0x01, 0x01]));
        Check(Read([0x02, 0x01, 0x00]));
        Check(Read([0x02, 0x02, 0x00, 0x80]));
        Check(Read([0x02, 0x02, 0xFF, 0x7F]));
        Check(!Read([0x02, 0x00]));
        Check(!Read([0x02, 0x02, 0x00, 0x7F]));
        Check(!Read([0x02, 0x02, 0xFF, 0x80]));
        Check(Read([0x03, 0x02, 0x03, 0xA8]));
        Check(!Read([0x03, 0x02, 0x03, 0xAB]));
        Check(!Read([0x03, 0x01, 0x01]));
        Check(Read([0x05, 0x00]));
        Check(!Read([0x05, 0x01, 0x00]));
        Check(Read([0x06, 0x03, 0x2A, 0x86, 0x48]));
        Check(!Read([0x06, 0x02, 0x80, 0x01]));
        Check(!Read([0x06, 0x02, 0x2A, 0x80]));
        Check(!Read([0x04, 0x81, 0x7F]));
        Check(!Read([0x04, 0x82, 0x00, 0x80]));
        Check(!Read([0x04, 0x80]));
        Check(!Read([0x1F, 0x01, 0x00]));
        Check(Read([0x9F, 0x1F, 0x01, 0x00]));
        Check(Read([0x9F, 0x81, 0x01, 0x00]));
        Check(!Read([0x9F, 0x1E, 0x00]));
        Check(!Read([0x9F, 0x80, 0x00]));
        Check(!Read([0x9F, 0x81, 0x81, 0x00, 0x00]));
        Check(!Read([0x20, 0x00]));
        Check(!Read([0x22, 0x01, 0x00]));
        Check(!Read([0x10, 0x00]));
        byte[] long128 = new byte[131];
        long128[0] = 4; long128[1] = 0x81; long128[2] = 0x80;
        Check(Read(long128));
        byte[] long256 = new byte[260];
        long256[0] = 4; long256[1] = 0x82; long256[2] = 1;
        Check(Read(long256));
        int[] unchangedResult = [9, 9, 9, 9, 9];
        Check(!Der.TryRead([2, 0], 0, 2, unchangedResult, 0));
        Check(unchangedResult[0] == 9 && unchangedResult[4] == 9);

        byte[] output = new byte[32];
        Check(Der.WriteInteger(output, 0, output.Length, 127) == 3);
        Check(output[0] == 0x02 && output[1] == 1 && output[2] == 0x7F);
        Check(Der.WriteInteger(output, 0, output.Length, 128) == 4);
        Check(output[2] == 0 && output[3] == 0x80);
        Check(Der.WriteInteger(output, 0, output.Length, -129) == 4);
        Check(output[2] == 0xFF && output[3] == 0x7F);

        byte[] value = [1, 2, 3];
        Check(Der.WriteOctetString(output, 2, 5, value, 0, value.Length) == 5);
        Check(output[2] == 4 && output[3] == 3 && output[4] == 1 && output[6] == 3);
        byte[] unchanged = [9, 9, 9, 9];
        Check(Der.WriteOctetString(unchanged, 0, 3, value, 0, value.Length) == -1);
        Check(unchanged[0] == 9 && unchanged[3] == 9);

        byte[] overlap = [1, 2, 3, 4, 5, 6];
        Check(Der.WriteOctetString(overlap, 0, overlap.Length, overlap, 0, 4) == 6);
        Check(overlap[0] == 4 && overlap[1] == 4 && overlap[2] == 1 && overlap[5] == 4);
        Check(Der.WriteBitString(output, 0, output.Length, 3, [0xA8], 0, 1) == 4);
        Check(output[0] == 3 && output[2] == 3 && output[3] == 0xA8);
        Check(Der.WriteBitString(output, 0, output.Length, 3, [0xAB], 0, 1) == -1);
        Check(Der.WriteBitString(output, 0, output.Length, 0, [0xA8], 2, 1) == -1);
        Check(Der.WriteObjectIdentifier(output, 0, output.Length, [0x2A, 0x86, 0x48], 0, 3) == 5);
        Check(Der.WriteObjectIdentifier(output, 0, output.Length, [0x80, 0x01], 0, 2) == -1);
        Check(Der.WriteTaggedPrimitive(output, 0, output.Length, 0x9F1F, [7], 0, 1) == 4);
        Check(output[0] == 0x9F && output[1] == 0x1F && output[2] == 1 && output[3] == 7);
        Check(Der.WriteTaggedPrimitive(output, 0, output.Length, 0x9F8101, [7], 0, 1) == 5);
        Check(output[0] == 0x9F && output[1] == 0x81 && output[2] == 1 && output[3] == 1 &&
            output[4] == 7);
        Check(Der.WriteTaggedPrimitive(output, 0, output.Length, 0x1F1F, [7], 0, 1) == -1);
        Check(Der.WriteTaggedPrimitive(output, 0, output.Length, 0xBF1F, [7], 0, 1) == -1);

        byte[] longOutput = new byte[260];
        Check(Der.WriteOctetString(longOutput, 0, longOutput.Length, new byte[128], 0, 128) == 131);
        Check(longOutput[0] == 4 && longOutput[1] == 0x81 && longOutput[2] == 0x80);

        byte[] encoded = [0x02, 0x01, 0x01, 0x05, 0x00];
        Check(Der.WriteSequence(output, 0, output.Length, encoded, 0, encoded.Length) == 7);
        Check(output[0] == 0x30 && output[1] == 5 && output[6] == 0);
        Check(Der.WriteSequence(output, 0, output.Length, [0x30, 0x00], 0, 2) == -1);
        Check(Der.WriteSequence(output, 0, output.Length, [0xA0, 0x00], 0, 2) == -1);

        byte[] nested = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
        int[] scratch = new int[Der.ResultSize + 3];
        Check(Der.TryValidate(nested, 0, nested.Length, scratch, 0, scratch.Length));
        Check(!Der.TryValidate(nested, 0, nested.Length, new int[Der.ResultSize + 1], 0,
            Der.ResultSize + 1));
        Check(!Der.TryValidate([0x30, 0x03, 0x02, 0x02, 0x01], 0, 5, scratch, 0, scratch.Length));
        Check(Der.WriteSequence(output, 0, output.Length, nested, 0, nested.Length,
            scratch, 0, scratch.Length) == 9);
        Check(output[0] == 0x30 && output[1] == 7 && output[8] == 1);
        Check(Der.WriteTaggedConstructed(output, 0, output.Length, 0xBF1F,
            nested, 0, nested.Length, scratch, 0, scratch.Length) == 10);
        Check(output[0] == 0xBF && output[1] == 0x1F && output[2] == 7);
        byte[] orderedSet = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        byte[] reversedSet = [0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        Check(Der.WriteSetOf(output, 0, output.Length, orderedSet, 0, orderedSet.Length,
            scratch, 0, scratch.Length) == 8);
        Check(output[0] == 0x31 && output[1] == 6);
        Check(Der.WriteSetOf(output, 0, output.Length, reversedSet, 0, reversedSet.Length,
            scratch, 0, scratch.Length) == -1);

        Console.WriteLine($"PASS: {assertions} DER boundary and canonical-form assertions");
    }
}
