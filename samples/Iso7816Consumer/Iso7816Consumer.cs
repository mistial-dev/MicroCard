using MicroCard.Framework;
using MicroCard.Iso7816;

[assembly: Dependency("MicroCard.Iso7816", "=0.1.0", Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

namespace MicroCard.Iso7816.Consumer;

[Assembly("F04D430781")]
public static class Iso7816Consumer
{
    [Process]
    public static void Process()
    {
        int commandLength = CommandApdu.Length;
        if (commandLength < 2)
        {
            ResponseApdu.SetStatus(StatusWords.WrongLength);
            return;
        }
        var command = new byte[commandLength];
        CommandApdu.CopyTo(command, 0, 0, command.Length);
        int mode = command[0];
        int length = command[1];
        if (length != commandLength - 2)
        {
            ResponseApdu.SetStatus(StatusWords.WrongLength);
            return;
        }

        byte[] input = new byte[length];
        for (int index = 0; index < length; index++)
            input[index] = command[index + 2];

        if (mode == 0)
            ParseSelect(input);
        else if (mode == 1)
            ParseTlv(input);
        else
            ResponseApdu.SetStatus(StatusWords.IncorrectParameters);
    }

    private static void ParseSelect(byte[] input)
    {
        int[] parsed = new int[ShortCommand.ResultSize];
        if (!ShortCommand.TryParse(input, 0, input.Length, parsed, 0) ||
            !CommandRouting.Matches(input, 0, input.Length, 0, 0xFC,
                Instructions.Select, 0x04, CommandRouting.Any) ||
            !Aid.IsValid(input, parsed[ShortCommand.DataOffsetIndex], parsed[ShortCommand.DataLengthIndex]))
        {
            ResponseApdu.SetStatus(StatusWords.IncorrectData);
            return;
        }

        int expected = parsed[ShortCommand.ExpectedLengthIndex];
        byte[] response = [(byte)parsed[ShortCommand.CaseIndex], (byte)parsed[ShortCommand.DataLengthIndex],
            (byte)(expected >> 8), (byte)expected];
        ResponseApdu.Write(response, 0, response.Length);
    }

    private static void ParseTlv(byte[] input)
    {
        int[] parsed = new int[BerTlv.ResultSize];
        if (!BerTlv.TryRead(input, 0, input.Length, parsed, 0) ||
            parsed[BerTlv.NextOffsetIndex] != input.Length)
        {
            ResponseApdu.SetStatus(StatusWords.IncorrectData);
            return;
        }

        int tag = parsed[BerTlv.TagIndex];
        int valueLength = parsed[BerTlv.ValueLengthIndex];
        byte[] response = [(byte)(tag >> 16), (byte)(tag >> 8), (byte)tag,
            (byte)(valueLength >> 8), (byte)valueLength];
        ResponseApdu.Write(response, 0, response.Length);
    }
}
