using MicroCard.Framework;
using MicroCard.Core;

[assembly: Dependency("mscorlib", "=0.1.0",
    ReferenceAssembly = "MicroCard.Core",
    Scope = DependencyScope.IssuerSecurityDomain,
    PackageVersion = 1,
    SignerPublicKeyHex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")]

namespace MicroCard.Samples.CoreConsumer;

[Assembly("F04D4309C0")]
public static class CoreConsumer
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
        var command = new byte[length];
        CommandApdu.CopyTo(command, 0, 0, length);
        int operation = command[0];
        if (operation == 0)
        {
            var response = new byte[5];
            response[0] = 1;
            response[1] = 2;
            response[2] = 3;
            response[3] = 4;
            response[4] = 5;
            ByteBuffer.Copy(response, 0, response, 1, 4);
            Write(response);
            return;
        }
        if (operation == 1)
        {
            var response = new byte[length - 1];
            ByteBuffer.Copy(command, 1, response, 0, response.Length);
            Write(response);
            return;
        }
        if (operation == 2)
        {
            if (length != 5)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            var response = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(response, 0,
                BinaryPrimitives.ReadInt32BigEndian(command, 1));
            Write(response);
            return;
        }
        if (operation == 3 || operation == 4)
        {
            int dataLength = length - 1;
            if ((dataLength & 1) != 0)
            {
                ResponseApdu.SetStatus(0x6700);
                return;
            }
            int half = dataLength / 2;
            int result = operation == 3
                ? (ByteBuffer.Equals(command, 1, command, 1 + half, half) ? 1 : 0)
                : ByteBuffer.Compare(command, 1, half, command, 1 + half, half) + 1;
            byte[] response = [(byte)result];
            Write(response);
            return;
        }
        if (operation == 5 && length == 2)
        {
            byte[] response = [(byte)Int32Math.Clamp(command[1], 10, 20)];
            Write(response);
            return;
        }
        ResponseApdu.SetStatus(0x6D00);
    }

    private static void Write(byte[] data) => ResponseApdu.Write(data, 0, data.Length);
}
