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

using var jcvmVector = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(args[0])!, "jcvm-manifest-cbor-v1.json")));
var jcvm = jcvmVector.RootElement;
var jcvmBytes = Convert.FromHexString(jcvm.GetProperty("hex").GetString()!);
if (!ManifestCbor.EncodeJcvm(jcvm.GetProperty("manifest")).AsSpan().SequenceEqual(jcvmBytes)
    || !ManifestCbor.EncodeJcvm(ManifestCbor.DecodeJcvm(jcvmBytes)).AsSpan().SequenceEqual(jcvmBytes))
    throw new Exception("JCVM manifest differs from shared vector");
void Reject(Action action)
{
    try { action(); }
    catch (Exception error) when (error is FormatException or InvalidDataException or InvalidOperationException or OverflowException or ArgumentException) { return; }
    throw new Exception("Accepted invalid device format");
}
foreach (var (offset, value) in new[] { (0, (byte)0x89), (1, (byte)2), (2, (byte)0) })
{
    var invalid = (byte[])jcvmBytes.Clone(); invalid[offset] = value;
    Reject(() => ManifestCbor.DecodeJcvm(invalid));
}
Reject(() => ManifestCbor.DecodeJcvm([..jcvmBytes, 0]));
foreach (var invalid in new[] { "65537", "512.5", "true", "\"512\"" })
{
    var changed = System.Text.Json.Nodes.JsonNode.Parse(jcvm.GetProperty("manifest").GetRawText())!;
    changed["limits"]!["heap_bytes"] = System.Text.Json.Nodes.JsonNode.Parse(invalid);
    Reject(() => ManifestCbor.EncodeJcvm(JsonSerializer.SerializeToElement(changed)));
}
Console.WriteLine("PASS: .NET JCVM manifest vector and bounded field rejection");

using var envelopeVector = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(args[0])!, "package-envelope-v5.json")));
var envelope = envelopeVector.RootElement;
byte[] Field(string name) => Convert.FromHexString(envelope.GetProperty(name).GetString()!);
var package = PackageEnvelope.Create(Field("manifest"), Field("image"), Field("seed"));
if (!package.AsSpan().SequenceEqual(Field("package"))) throw new Exception("MP05 differs from independent vector");
var verified = PackageEnvelope.Verify(package);
if (!verified.Manifest.AsSpan().SequenceEqual(Field("manifest")) || !verified.Image.AsSpan().SequenceEqual(Field("image")))
    throw new Exception("MP05 decoded fields differ");
var largerImage = new byte[17 * 1024];
Reject(() => PackageEnvelope.Create(jcvmBytes, largerImage, Field("seed")));
var largerPackage = PackageEnvelope.Create(jcvmBytes, largerImage, Field("seed"), 60 * 1024);
Reject(() => PackageEnvelope.Verify(largerPackage));
if (!PackageEnvelope.Verify(largerPackage, 60 * 1024).Image.AsSpan().SequenceEqual(largerImage))
    throw new Exception("Bounded envelope lost image bytes");
for (int i = 0; i < package.Length; i++)
{
    var changed = (byte[])package.Clone(); changed[i] ^= 1;
    bool rejected = false;
    try { PackageEnvelope.Verify(changed); }
    catch (Exception error) when (error is InvalidDataException or OverflowException or ArgumentException) { rejected = true; }
    if (!rejected) throw new Exception($"MP05 accepted changed byte {i}");
}
Console.WriteLine("PASS: .NET MP05 independent vector and signature coverage");
