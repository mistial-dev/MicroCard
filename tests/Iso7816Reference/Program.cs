using System;
using MicroCard.Iso7816;

namespace MicroCard.Iso7816.Tests;

internal static class Program
{
    private static int assertions;

    private static void Main()
    {
        ParseShortCommands();
        CompareAidsAndRoute();
        ReadTlv();
        WriteTlv();
        Console.WriteLine($"PASS: {assertions} ISO 7816 helper assertions");
    }

    private static void ParseShortCommands()
    {
        int[] parsed = new int[ShortCommand.ResultSize];
        Check(ShortCommand.TryParse([0, 0x84, 0, 0], 0, 4, parsed, 0));
        Check(parsed[ShortCommand.CaseIndex] == ShortCommand.Case1);
        Check(parsed[ShortCommand.ExpectedLengthIndex] == ShortCommand.NoExpectedLength);

        Check(ShortCommand.TryParse([0, 0x84, 0, 0, 0], 0, 5, parsed, 0));
        Check(parsed[ShortCommand.CaseIndex] == ShortCommand.Case2);
        Check(parsed[ShortCommand.ExpectedLengthIndex] == 256);

        Check(ShortCommand.TryParse([0, 0xDA, 0, 0, 2, 0xCA, 0xFE], 0, 7, parsed, 0));
        Check(parsed[ShortCommand.CaseIndex] == ShortCommand.Case3);
        Check(parsed[ShortCommand.DataOffsetIndex] == 5 && parsed[ShortCommand.DataLengthIndex] == 2);

        Check(ShortCommand.TryParse([0, 0xCA, 0, 0, 2, 0xCA, 0xFE, 16], 0, 8, parsed, 0));
        Check(parsed[ShortCommand.CaseIndex] == ShortCommand.Case4);
        Check(parsed[ShortCommand.ExpectedLengthIndex] == 16);
        Check(!ShortCommand.TryParse([0, 0xCA, 0, 0, 0, 1], 0, 6, parsed, 0));
        Check(!ShortCommand.TryParse([0, 0, 0], 0, 3, parsed, 0));
        Check(!ShortCommand.TryParse([0, 0, 0, 0], 1, 4, parsed, 0));
    }

    private static void CompareAidsAndRoute()
    {
        byte[] left = [0xFF, 0xA0, 0, 0, 1, 1, 0xEE];
        byte[] right = [0xA0, 0, 0, 1, 1];
        Check(Aid.Equals(left, 1, 5, right, 0, 5));
        right[4] = 2;
        Check(!Aid.Equals(left, 1, 5, right, 0, 5));
        Check(!Aid.IsValid(right, 0, 4));

        byte[] select = [0x04, Instructions.Select, 0x04, 0x00];
        Check(CommandRouting.Matches(select, 0, select.Length, 0, 0xF0,
            Instructions.Select, 0x04, CommandRouting.Any));
        Check(!CommandRouting.Matches(select, 0, select.Length, 0, 0xFF,
            Instructions.GetData, CommandRouting.Any, CommandRouting.Any));
        Check(StatusWords.Success == 0x9000 && StatusWords.WrongLength == 0x6700);
    }

    private static void ReadTlv()
    {
        int[] parsed = new int[BerTlv.ResultSize];
        byte[] simple = [0x5A, 3, 1, 2, 3, 0x90];
        Check(BerTlv.TryRead(simple, 0, 5, parsed, 0));
        Check(parsed[BerTlv.TagIndex] == 0x5A);
        Check(parsed[BerTlv.HeaderLengthIndex] == 2);
        Check(parsed[BerTlv.ValueOffsetIndex] == 2 && parsed[BerTlv.ValueLengthIndex] == 3);
        Check(parsed[BerTlv.NextOffsetIndex] == 5);

        byte[] longTag = new byte[134];
        longTag[1] = 0x7F;
        longTag[2] = 0x21;
        longTag[3] = 0x81;
        longTag[4] = 0x80;
        Check(BerTlv.TryRead(longTag, 1, 133, parsed, 0));
        Check(parsed[BerTlv.TagIndex] == 0x7F21 && parsed[BerTlv.ValueLengthIndex] == 128);

        Check(!BerTlv.TryRead([0x5A, 0x81, 0x7F], 0, 3, parsed, 0));
        Check(!BerTlv.TryRead([0x5A, 0x80], 0, 2, parsed, 0));
        Check(!BerTlv.TryRead([0x7F, 0x80, 0], 0, 3, parsed, 0));
        Check(!BerTlv.TryRead([0x7F, 0x1E, 0], 0, 3, parsed, 0));
        Check(!BerTlv.TryRead([0, 0], 0, 2, parsed, 0));
        Check(!BerTlv.TryRead([0x5A, 2, 1], 0, 3, parsed, 0));
    }

    private static void WriteTlv()
    {
        byte[] output = new byte[140];
        byte[] value = [9, 8, 7];
        int written = BerTlv.Write(output, 2, 10, 0x5A, value, 0, value.Length);
        Check(written == 5);
        Check(output[2] == 0x5A && output[3] == 3 && output[4] == 9 && output[6] == 7);

        Check(BerTlv.WriteHeader(output, 0, output.Length, 0x7F21, 128) == 4);
        Check(output[0] == 0x7F && output[1] == 0x21 && output[2] == 0x81 && output[3] == 0x80);
        Check(BerTlv.WriteHeader(output, 0, output.Length, 0x5F8101, 256) == 6);
        Check(BerTlv.WriteHeader(output, 0, 1, 0x5A, 1) == -1);
        Check(BerTlv.WriteHeader(output, 0, output.Length, 0x1F, 1) == -1);
        Check(BerTlv.Write(output, 139, 1, 0x5A, value, 0, value.Length) == -1);

        byte[] overlap = [1, 2, 3, 0, 0];
        Check(BerTlv.Write(overlap, 0, overlap.Length, 0x5A, overlap, 0, 3) == 5);
        Check(overlap[2] == 1 && overlap[3] == 2 && overlap[4] == 3);
    }

    private static void Check(bool condition)
    {
        assertions++;
        if (!condition)
            throw new InvalidOperationException($"Assertion {assertions} failed");
    }
}
