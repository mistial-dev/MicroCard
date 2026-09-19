using MicroCard.Build;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string Usage = "usage: MicroCard.Bundle create OUTPUT SEED PACKAGE... --explicit-sign\n       MicroCard.Bundle verify BUNDLE PACKAGE...";
ReadOnlySpan<byte> magic = "MDB2"u8;
ReadOnlySpan<byte> context = "MicroCard default bundle v2\0"u8;

try
{
    if (args.Length >= 5 && args[0] == "create" && args[^1] == "--explicit-sign")
    {
        var seed = File.ReadAllBytes(args[2]);
        try
        {
            if (seed.Length != 32) throw new InvalidDataException("P-256 seed must be 32 bytes");
            var signer = PackageSignatures.PublicKey(seed);
            var packages = LoadPackages(args[3..^1], signer);
            var body = EncodeBody(packages, signer);
            var output = body.Concat(PackageSignatures.Sign(seed, body)).ToArray();
            File.WriteAllBytes(args[1], output);
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    if (args.Length >= 3 && args[0] == "verify")
    {
        var encoded = File.ReadAllBytes(args[1]);
        if (encoded.Length < 4 + context.Length + 1 + 16 + 65 + 64) throw new InvalidDataException("Truncated bundle");
        if (!encoded.AsSpan(0, 4).SequenceEqual(magic) || !encoded.AsSpan(4, context.Length).SequenceEqual(context))
            throw new InvalidDataException("Unsupported bundle format");
        var body = encoded.AsSpan(0, encoded.Length - 64);
        var signature = encoded.AsSpan(encoded.Length - 64);
        var signerOffset = 4 + context.Length + 1 + 16;
        var signer = body.Slice(signerOffset, 65).ToArray();
        if (!PackageSignatures.Verify(signer, body.ToArray(), signature.ToArray())) throw new InvalidDataException("Invalid bundle signature");
        var packages = LoadPackages(args[2..], signer);
        var expected = EncodeBody(packages, signer);
        if (!body.SequenceEqual(expected)) throw new InvalidDataException("Bundle does not match the supplied packages");
        Console.WriteLine($"verified {packages.Count} default assemblies");
        return 0;
    }

    Console.Error.WriteLine(Usage);
    return 2;
}
catch (Exception error)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}

static List<PackageRecord> LoadPackages(string[] paths, byte[] requiredSigner)
{
    if (paths.Length == 0 || paths.Length > byte.MaxValue) throw new InvalidDataException("Bundle must contain 1 through 255 packages");
    var packages = paths.Select(ReadPackage).ToDictionary(package => package.Assembly, StringComparer.Ordinal);
    if (packages.Count != paths.Length) throw new InvalidDataException("Duplicate assembly identity");
    foreach (var package in packages.Values)
    {
        if (package.Domain != "ISD") throw new InvalidDataException($"{package.Assembly} is not targeted to the ISD");
        if (!package.Signer.SequenceEqual(requiredSigner)) throw new InvalidDataException($"{package.Assembly} uses a different signer");
        foreach (var dependency in package.Dependencies)
            if (!packages.ContainsKey(dependency)) throw new InvalidDataException($"{package.Assembly} has external dependency {dependency}");
    }
    if (!packages.TryGetValue("mscorlib", out var core) || core.Dependencies.Count != 0)
        throw new InvalidDataException("The bundle must contain dependency-free mscorlib");
    if (packages.Values.Any(package => !package.Incarnation.SequenceEqual(core.Incarnation)))
        throw new InvalidDataException("Packages target different ISD incarnations");

    var ordered = new List<PackageRecord>(packages.Count) { core };
    var remaining = new SortedSet<string>(packages.Keys, StringComparer.Ordinal);
    remaining.Remove("mscorlib");
    while (remaining.Count != 0)
    {
        var next = remaining.FirstOrDefault(name => packages[name].Dependencies.All(dependency => ordered.Any(done => done.Assembly == dependency)));
        if (next is null) throw new InvalidDataException("Dependency cycle in default bundle");
        ordered.Add(packages[next]);
        remaining.Remove(next);
    }
    if (ordered[0].Assembly != "mscorlib") throw new InvalidDataException("mscorlib is not the first load");
    return ordered;
}

static PackageRecord ReadPackage(string path)
{
    var bytes = File.ReadAllBytes(path);
    var packageContext = "MicroCard signed package v4\0"u8;
    const int fixedHeader = 4 + 28 + 8;
    if (bytes.Length < fixedHeader + 129 || !bytes.AsSpan(0, 4).SequenceEqual("MP04"u8) ||
        !bytes.AsSpan(4, packageContext.Length).SequenceEqual(packageContext))
        throw new InvalidDataException($"Invalid package: {path}");
    var manifestLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4 + packageContext.Length, 4)));
    var imageLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8 + packageContext.Length, 4)));
    var signedLength = checked(fixedHeader + manifestLength + imageLength + 65);
    if (signedLength + 64 != bytes.Length) throw new InvalidDataException($"Invalid package length: {path}");
    var signer = bytes.AsSpan(signedLength - 65, 65).ToArray();
    if (!PackageSignatures.Verify(signer, bytes.AsSpan(0, signedLength).ToArray(), bytes.AsSpan(signedLength, 64).ToArray()))
        throw new InvalidDataException($"Invalid package signature: {path}");
    using var document = JsonDocument.Parse(bytes.AsMemory(fixedHeader, manifestLength));
    var root = document.RootElement;
    var version = root.GetProperty("assembly_version").EnumerateArray().Select(value => checked((ushort)value.GetInt32())).ToArray();
    if (version.Length != 4) throw new InvalidDataException($"Invalid assembly version: {path}");
    var dependencies = root.GetProperty("dependencies").EnumerateArray()
        .Select(value => value.GetProperty("assembly").GetString() ?? throw new InvalidDataException("Missing dependency identity"))
        .ToArray();
    var incarnation = root.GetProperty("incarnation").EnumerateArray().Select(value => checked((byte)value.GetInt32())).ToArray();
    if (incarnation.Length != 16) throw new InvalidDataException($"Invalid incarnation: {path}");
    return new PackageRecord(
        root.GetProperty("assembly").GetString() ?? throw new InvalidDataException("Missing assembly identity"),
        root.GetProperty("domain").GetString() ?? throw new InvalidDataException("Missing domain"),
        incarnation,
        version,
        checked((uint)root.GetProperty("version").GetInt64()),
        dependencies,
        signer,
        SHA256.HashData(bytes.AsSpan(fixedHeader + manifestLength, imageLength)),
        SHA256.HashData(bytes));
}

static byte[] EncodeBody(List<PackageRecord> packages, byte[] signer)
{
    using var output = new MemoryStream();
    using var writer = new BinaryWriter(output, Encoding.UTF8, true);
    writer.Write("MDB2"u8);
    writer.Write("MicroCard default bundle v2\0"u8);
    writer.Write(checked((byte)packages.Count));
    writer.Write(packages[0].Incarnation);
    writer.Write(signer);
    foreach (var package in packages)
    {
        var name = Encoding.UTF8.GetBytes(package.Assembly);
        if (name.Length == 0 || name.Length > 64) throw new InvalidDataException("Assembly identity must be 1 through 64 UTF-8 bytes");
        writer.Write(checked((byte)name.Length));
        writer.Write(name);
        foreach (var part in package.AssemblyVersion) writer.Write(part);
        writer.Write(package.PackageVersion);
        writer.Write(package.ImageDigest);
        writer.Write(package.PackageDigest);
    }
    return output.ToArray();
}

sealed record PackageRecord(string Assembly, string Domain, byte[] Incarnation, ushort[] AssemblyVersion,
    uint PackageVersion, IReadOnlyList<string> Dependencies, byte[] Signer, byte[] ImageDigest, byte[] PackageDigest);
