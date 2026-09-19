using System.Text.Json;
using MicroCard.Build;

if (args.Length != 1) throw new ArgumentException("Pass the manifest vector path");
using var vectors = JsonDocument.Parse(File.ReadAllBytes(args[0]));
foreach (var vector in vectors.RootElement.EnumerateArray())
{
    var expected = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
    var actual = ManifestCbor.Encode(vector.GetProperty("manifest"));
    if (!actual.AsSpan().SequenceEqual(expected)) throw new Exception("CBOR manifest differs from shared vector");
}
Console.WriteLine("PASS: .NET manifest CBOR shared vectors");
