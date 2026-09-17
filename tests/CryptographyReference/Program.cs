using System;

namespace MicroCard.Cryptography.Tests;

public static class Program
{
    public static void Main()
    {
        byte[] source = [0xAA, 1, 2, 3, 4, 0xBB];
        var destination = new byte[40];
        Array.Fill(destination, (byte)0xCC);
        Require(MicroCard.Cryptography.SHA256.HashData(source, 1, 4, destination, 4) == 32,
            "written length");

        byte[] expected = System.Security.Cryptography.SHA256.HashData(source.AsSpan(1, 4));
        Require(destination.AsSpan(4, 32).SequenceEqual(expected), "offset hash");
        Require(destination.AsSpan(0, 4).SequenceEqual(new byte[4] { 0xCC, 0xCC, 0xCC, 0xCC }),
            "prefix preserved");
        Require(destination.AsSpan(36, 4).SequenceEqual(new byte[4] { 0xCC, 0xCC, 0xCC, 0xCC }),
            "suffix preserved");
        Require(MicroCard.Cryptography.SHA256.HashData(source).AsSpan().SequenceEqual(
            System.Security.Cryptography.SHA256.HashData(source)), "array hash");

        var aliased = new byte[40];
        source.AsSpan(1, 4).CopyTo(aliased.AsSpan(8));
        MicroCard.Cryptography.SHA256.HashData(aliased, 8, 4, aliased, 0);
        Require(aliased.AsSpan(0, 32).SequenceEqual(expected), "aliased ranges");

        Reject(() => MicroCard.Cryptography.SHA256.HashData(source, -1, 1, destination, 0));
        Reject(() => MicroCard.Cryptography.SHA256.HashData(source, 1, source.Length,
            destination, 0));
        Reject(() => MicroCard.Cryptography.SHA256.HashData(source, 0, source.Length,
            destination, 9));
        var random = MicroCard.Cryptography.RandomNumberGenerator.GetBytes(32);
        Require(random.Length == 32, "random length");
        Require(!random.AsSpan().SequenceEqual(new byte[32]), "random output");
        Require(MicroCard.Cryptography.RandomNumberGenerator.GetBytes(0).Length == 0,
            "empty random output");
        Reject(() => MicroCard.Cryptography.RandomNumberGenerator.GetBytes(-1));
        Reject(() => MicroCard.Cryptography.RandomNumberGenerator.GetBytes(1025));
        byte[] first = [9, 1, 2, 3, 8];
        byte[] second = [7, 1, 2, 3, 6];
        Require(MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, 1, 3,
            second, 1, 3), "equal ranges");
        Require(!MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, second),
            "different arrays");
        second[2] = 4;
        Require(!MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, 1, 3,
            second, 1, 3), "different ranges");
        Require(!MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(new byte[1],
            new byte[2]), "different lengths");
        Require(MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, 1, 3,
            first, 1, 3), "aliased range");
        Reject(() => MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, -1, 1,
            second, 0, 1));
        Reject(() => MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals(first, 0, 1,
            second, 4, 2));
        Console.WriteLine("PASS: 21 managed cryptography assertions");
    }

    private static void Reject(Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentOutOfRangeException)
        {
            return;
        }
        throw new Exception("Expected range rejection");
    }

    private static void Require(bool condition, string name)
    {
        if (!condition) throw new Exception(name);
    }
}
