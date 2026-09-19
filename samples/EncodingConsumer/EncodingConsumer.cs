using MicroCard.Framework;
using MicroCard.Encoding;

[assembly: Dependency("MicroCard.Encoding", "=0.1.0", Scope = DependencyScope.IssuerSecurityDomain,
    SignerPublicKeyHex = "2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")]

namespace MicroCard.Encoding.Consumer;

[Assembly("F04D430690")]
public static class EncodingConsumer
{
    [Process]
    public static void Process()
    {
        int length = CommandApdu.Length;
        if (length < 1)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        byte[] command = new byte[length];
        CommandApdu.CopyTo(command, 0, 0, length);
        int mode = command[0];
        if (mode == 0)
            Read(command, 1, length - 1);
        else if (mode == 1)
            WriteInteger(command);
        else if (mode == 2)
            WriteSequence(command, 1, length - 1);
        else if (mode == 3)
            WriteOctetString(command, 1, length - 1);
        else if (mode == 4)
            WriteOverlappingOctetString();
        else if (mode == 5)
            ValidateNested(command, 1, length - 1);
        else if (mode == 6)
            WriteTagged(command, 1, length - 1);
        else if (mode == 7)
            WriteSetOf(command, 1, length - 1);
        else
            ResponseApdu.SetStatus(0x6A86);
    }

    private static void Read(byte[] command, int offset, int length)
    {
        int[] parsed = new int[Der.ResultSize];
        if (!Der.TryRead(command, offset, length, parsed, 0) ||
            parsed[Der.NextOffsetIndex] != offset + length)
        {
            ResponseApdu.SetStatus(0x6A80);
            return;
        }
        byte[] response = [(byte)(parsed[Der.TagIndex] >> 16),
            (byte)(parsed[Der.TagIndex] >> 8), (byte)parsed[Der.TagIndex],
            (byte)parsed[Der.HeaderLengthIndex],
            (byte)(parsed[Der.ValueLengthIndex] >> 8), (byte)parsed[Der.ValueLengthIndex]];
        ResponseApdu.Write(response, 0, response.Length);
    }

    private static void WriteInteger(byte[] command)
    {
        if (command.Length != 5)
        {
            ResponseApdu.SetStatus(0x6700);
            return;
        }
        int value = command[1] << 24 | command[2] << 16 | command[3] << 8 | command[4];
        byte[] response = new byte[6];
        int written = Der.WriteInteger(response, 0, response.Length, value);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(response, 0, written);
    }

    private static void WriteSequence(byte[] command, int offset, int length)
    {
        byte[] response = new byte[length + 4];
        int written = Der.WriteSequence(response, 0, response.Length, command, offset, length);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(response, 0, written);
    }

    private static void WriteOctetString(byte[] command, int offset, int length)
    {
        byte[] response = new byte[length + 4];
        int written = Der.WriteOctetString(response, 0, response.Length, command, offset, length);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(response, 0, written);
    }

    private static void WriteOverlappingOctetString()
    {
        byte[] buffer = new byte[6];
        for (int index = 0; index < buffer.Length; index++)
            buffer[index] = (byte)(index + 1);
        int written = Der.WriteOctetString(buffer, 0, buffer.Length, buffer, 0, 4);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(buffer, 0, written);
    }

    private static void ValidateNested(byte[] command, int offset, int length)
    {
        int[] scratch = new int[Der.ResultSize + (length >> 1) + 1];
        if (!Der.TryValidate(command, offset, length, scratch, 0, scratch.Length))
        {
            ResponseApdu.SetStatus(0x6A80);
            return;
        }
        byte[] response = [1];
        ResponseApdu.Write(response, 0, response.Length);
    }

    private static void WriteTagged(byte[] command, int offset, int length)
    {
        byte[] response = new byte[length + 4];
        int written = Der.WriteTaggedPrimitive(response, 0, response.Length, 0x9F1F,
            command, offset, length);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(response, 0, written);
    }

    private static void WriteSetOf(byte[] command, int offset, int length)
    {
        int[] scratch = new int[Der.ResultSize + (length >> 1) + 1];
        byte[] response = new byte[length + 4];
        int written = Der.WriteSetOf(response, 0, response.Length, command, offset, length,
            scratch, 0, scratch.Length);
        if (written < 0)
            ResponseApdu.SetStatus(0x6A80);
        else
            ResponseApdu.Write(response, 0, written);
    }
}
