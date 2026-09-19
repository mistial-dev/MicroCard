using System.Text.Json;
using MicroCard.Build;

if (args.Length != 1) throw new ArgumentException("Pass the manifest vector path");
using var vectors = JsonDocument.Parse(File.ReadAllBytes(args[0]));
foreach (var vector in vectors.RootElement.EnumerateArray())
{
    var expected = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
    var actual = ManifestCbor.Encode(vector.GetProperty("manifest"));
    if (!ManifestCbor.Encode(ManifestCbor.Decode(actual)).AsSpan().SequenceEqual(expected)) throw new Exception("CBOR decode differs from shared vector");
    if (!actual.AsSpan().SequenceEqual(expected)) throw new Exception("CBOR manifest differs from shared vector");
}
Console.WriteLine("PASS: .NET manifest CBOR shared vectors");

using var envelopeVector = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(args[0])!, "package-envelope-v5.json")));
var envelope = envelopeVector.RootElement;
byte[] Field(string name) => Convert.FromHexString(envelope.GetProperty(name).GetString()!);
var package = PackageEnvelope.Create(Field("manifest"), Field("image"), Field("seed"));
if (!package.AsSpan().SequenceEqual(Field("package"))) throw new Exception("MP05 differs from independent vector");
var verified = PackageEnvelope.Verify(package);
if (!verified.Manifest.AsSpan().SequenceEqual(Field("manifest")) || !verified.Image.AsSpan().SequenceEqual(Field("image")))
    throw new Exception("MP05 decoded fields differ");
for (int i = 0; i < package.Length; i++)
{
    var changed = (byte[])package.Clone(); changed[i] ^= 1;
    bool rejected = false;
    try { PackageEnvelope.Verify(changed); }
    catch (Exception error) when (error is InvalidDataException or OverflowException or ArgumentException) { rejected = true; }
    if (!rejected) throw new Exception($"MP05 accepted changed byte {i}");
}
Console.WriteLine("PASS: .NET MP05 independent vector and signature coverage");
