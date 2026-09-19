using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace MicroCard.Build;

/// <summary>Fixed-field version-1 manifest CBOR for the next package envelope.</summary>
internal static class ManifestCbor
{
    public static byte[] Encode(JsonElement value)
    {
        using var output = new MemoryStream();
        void Argument(byte major, ulong value)
        {
            Span<byte> bytes = stackalloc byte[9];
            int length;
            byte additional;
            if (value < 24) { additional = (byte)value; length = 0; }
            else if (value <= byte.MaxValue) { additional = 24; length = 1; }
            else if (value <= ushort.MaxValue) { additional = 25; length = 2; }
            else if (value <= uint.MaxValue) { additional = 26; length = 4; }
            else { additional = 27; length = 8; }
            bytes[0] = (byte)((major << 5) | additional);
            Span<byte> integer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(integer, value);
            integer[(8 - length)..].CopyTo(bytes[1..]);
            output.Write(bytes[..(length + 1)]);
        }
        void Array(int count) => Argument(4, checked((ulong)count));
        void Number(JsonElement number) => Argument(0, number.GetUInt64());
        void Bytes(byte[] bytes) { Argument(2, (ulong)bytes.Length); output.Write(bytes); }
        void Text(JsonElement text)
        {
            string name = text.GetString() ?? throw new FormatException("Missing identifier");
            if (!EmbeddedIdentifier.IsValid(name)) throw new FormatException("Invalid identifier");
            byte[] bytes = Encoding.ASCII.GetBytes(name);
            Argument(3, (ulong)bytes.Length); output.Write(bytes);
        }
        void Binary(JsonElement bytes, int length)
        {
            byte[] raw = bytes.EnumerateArray().Select(item => item.GetByte()).ToArray();
            if (raw.Length != length) throw new FormatException("Invalid binary field length");
            Bytes(raw);
        }
        void Version(JsonElement version)
        {
            if (version.GetArrayLength() != 4) throw new FormatException("Invalid assembly version");
            Array(4); foreach (var part in version.EnumerateArray()) Argument(0, part.GetUInt16());
        }
        void Optional(JsonElement item, Action<JsonElement> write)
        {
            if (item.ValueKind == JsonValueKind.Null) output.WriteByte(0xf6); else write(item);
        }
        void Boolean(JsonElement item) => output.WriteByte(item.GetBoolean() ? (byte)0xf5 : (byte)0xf4);
        JsonElement Collection(string name, int maximum)
        {
            var collection = value.GetProperty(name);
            if (collection.GetArrayLength() > maximum) throw new FormatException("Manifest collection quota exceeded");
            return collection;
        }
        Array(12); Argument(0, 1); Text(value.GetProperty("domain")); Binary(value.GetProperty("incarnation"), 16);
        Text(value.GetProperty("assembly")); Version(value.GetProperty("assembly_version")); Number(value.GetProperty("version"));
        var export = value.GetProperty("export"); Array(2); Number(export.GetProperty("access"));
        Optional(export.GetProperty("key"), item => Binary(item, 32));
        var entries = Collection("entry_points", 4); Array(entries.GetArrayLength());
        foreach (var entry in entries.EnumerateArray())
        {
            Array(6); string aid = entry.GetProperty("aid").GetString()!;
            if (aid.Length < 10 || aid.Length > 32 || aid.Length % 2 != 0 || aid.Any(c => !char.IsAsciiHexDigitUpper(c)))
                throw new FormatException("Invalid AID");
            Bytes(Convert.FromHexString(aid)); Number(entry.GetProperty("process"));
            foreach (string field in new[] { "install", "uninstall", "select", "deselect" }) Optional(entry.GetProperty(field), Number);
        }
        var dependencies = Collection("dependencies", 16); Array(dependencies.GetArrayLength());
        foreach (var dependency in dependencies.EnumerateArray())
        {
            Array(6); Text(dependency.GetProperty("assembly")); var ranges = dependency.GetProperty("ranges");
            if (ranges.GetArrayLength() is < 1 or > 8) throw new FormatException("Invalid dependency range count");
            Array(ranges.GetArrayLength());
            foreach (var range in ranges.EnumerateArray())
            {
                Array(4); Optional(range.GetProperty("min"), Version); Boolean(range.GetProperty("min_inclusive"));
                Optional(range.GetProperty("max"), Version); Boolean(range.GetProperty("max_inclusive"));
            }
            Number(dependency.GetProperty("package_version"));
            Optional(dependency.GetProperty("signer"), item => Binary(item, 32));
            Optional(dependency.GetProperty("digest"), item => Binary(item, 32)); Number(dependency.GetProperty("scope"));
        }
        var capabilities = Collection("capabilities", 35); Binary(capabilities, capabilities.GetArrayLength());
        var storage = Collection("storage", 64); Array(storage.GetArrayLength());
        foreach (var declaration in storage.EnumerateArray())
        {
            Array(3); Number(declaration.GetProperty("key")); Number(declaration.GetProperty("kind")); Number(declaration.GetProperty("max_bytes"));
        }
        Array(4); var limits = value.GetProperty("limits");
        foreach (string field in new[] { "arena", "stack", "frames", "instructions" }) Number(limits.GetProperty(field));
        if (output.Length > 16384) throw new FormatException("Manifest quota exceeded");
        return output.ToArray();
    }
}
