using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

sealed partial class Mc04Writer : IDisposable
{
    readonly FileStream file;
    readonly PEReader pe;
    readonly MetadataReader md;
    readonly string frameworkName;
    readonly byte[] frameworkHash;
    readonly string deviceAssemblyName;
    readonly IReadOnlyDictionary<string, string> referenceAliases;
    readonly AssemblyReferenceHandle frameworkReference;
    readonly Dictionary<TypeDefinitionHandle, ushort> typeDefs;
    readonly Dictionary<TypeReferenceHandle, ushort> typeRefs;
    readonly Dictionary<FieldDefinitionHandle, ushort> fields;
    readonly Dictionary<MethodDefinitionHandle, ushort> methods;
    readonly Dictionary<MemberReferenceHandle, ushort> memberRefs;
    readonly Dictionary<AssemblyReferenceHandle, ushort> assemblyRefs;
    readonly Dictionary<MethodDefinitionHandle, byte[]> methodCode = new();
    readonly HashSet<MethodDefinitionHandle> transactionalMethods = new();
    readonly Dictionary<TypeReferenceHandle, string> projectedTransactionTypes = new();
    readonly Dictionary<MemberReferenceHandle, (string Name, bool Staticize)> projectedTransactionMembers = new();
    readonly Dictionary<byte, ushort> emptyArrayTypeRows = new();
    readonly List<(EntityHandle Scope, string Name)> syntheticTypeRefs = new();
    readonly StringHeap strings = new();
    readonly BlobHeap blobs = new();

    Mc04Writer(string input, string frameworkName, byte[] frameworkHash, string deviceAssemblyName,
        IReadOnlyDictionary<string, string> referenceAliases)
    {
        this.frameworkName = frameworkName;
        this.frameworkHash = frameworkHash;
        this.deviceAssemblyName = deviceAssemblyName;
        this.referenceAliases = referenceAliases;
        file = File.OpenRead(input);
        pe = new PEReader(file);
        md = pe.GetMetadataReader();
        frameworkReference = md.AssemblyReferences.Single(handle =>
            md.GetString(md.GetAssemblyReference(handle).Name) == frameworkName);
        typeDefs = Rows(md.TypeDefinitions);
        // Literal Int32 constants are embedded in CIL at every use and need no runtime row.
        fields = Rows(md.FieldDefinitions.Where(handle =>
            (md.GetFieldDefinition(handle).Attributes & System.Reflection.FieldAttributes.Literal) == 0));
        methods = Rows(md.MethodDefinitions);
        var usedMembers = new HashSet<MemberReferenceHandle>();
        var usedTypes = new HashSet<TypeReferenceHandle>();
        var emptyArrayScopes = new Dictionary<byte, EntityHandle>();
        foreach (var (_, attribute) in RuntimeAttributes())
            if (md.GetCustomAttribute(attribute).Constructor.Kind == HandleKind.MemberReference)
                usedMembers.Add((MemberReferenceHandle)md.GetCustomAttribute(attribute).Constructor);
        foreach (var handle in md.TypeDefinitions)
        {
            var parent = md.GetTypeDefinition(handle).BaseType;
            if (parent.Kind == HandleKind.TypeReference) usedTypes.Add((TypeReferenceHandle)parent);
        }
        foreach (var handle in fields.Keys) CollectSignature(md.GetBlobBytes(md.GetFieldDefinition(handle).Signature), usedTypes);
        foreach (var handle in md.MethodDefinitions)
        {
            var definition = md.GetMethodDefinition(handle);
            CollectSignature(md.GetBlobBytes(definition.Signature), usedTypes);
            var body = pe.GetMethodBody(definition.RelativeVirtualAddress);
            if (!body.LocalSignature.IsNil) CollectSignature(md.GetBlobBytes(md.GetStandaloneSignature(body.LocalSignature).Signature), usedTypes);
            var code = RewriteTransactionScope(body);
            methodCode.Add(handle, code);
            foreach (var token in CilTokens(code))
            {
                if (token.Kind == HandleKind.MemberReference) usedMembers.Add((MemberReferenceHandle)token);
                if (token.Kind == HandleKind.TypeReference) usedTypes.Add((TypeReferenceHandle)token);
                if (token.Kind == HandleKind.MethodSpecification)
                {
                    if (!TryGetEmptyArrayElement(token, out byte element, out var scope))
                        throw new Exception("Generic method specifications are outside the MC04 profile");
                    if (emptyArrayScopes.TryGetValue(element, out var previous) && previous != scope)
                        throw new Exception("Inconsistent System.Array resolution scopes");
                    emptyArrayScopes[element] = scope;
                }
            }
        }
        foreach (var handle in usedMembers)
        {
            var member = md.GetMemberReference(handle);
            if (member.Parent.Kind == HandleKind.TypeReference &&
                IsSystemTransactions((TypeReferenceHandle)member.Parent) &&
                !projectedTransactionMembers.ContainsKey(handle) &&
                !ProjectTransactionQuery(handle))
                throw new Exception("Unsupported System.Transactions member");
            if (member.Parent.Kind == HandleKind.TypeReference &&
                IsProjectedSystemCryptography((TypeReferenceHandle)member.Parent) &&
                !IsProjectedSystemCryptography(handle))
                throw new Exception("Unsupported System.Security.Cryptography member");
            if (member.Parent.Kind == HandleKind.TypeReference) usedTypes.Add((TypeReferenceHandle)member.Parent);
            CollectSignature(md.GetBlobBytes(member.Signature), usedTypes);
        }
        var usedAssemblies = new HashSet<AssemblyReferenceHandle>();
        var pending = new Queue<TypeReferenceHandle>(usedTypes);
        while (pending.TryDequeue(out var handle))
        {
            var scope = md.GetTypeReference(handle).ResolutionScope;
            if (IsProjectedType(handle)) usedAssemblies.Add(frameworkReference);
            else if (scope.Kind == HandleKind.AssemblyReference) usedAssemblies.Add((AssemblyReferenceHandle)scope);
            else if (scope.Kind == HandleKind.TypeReference && usedTypes.Add((TypeReferenceHandle)scope)) pending.Enqueue((TypeReferenceHandle)scope);
        }
        foreach (var scope in emptyArrayScopes.Values)
        {
            if (scope.Kind != HandleKind.AssemblyReference)
                throw new Exception("System.Array must resolve through an assembly reference");
            usedAssemblies.Add((AssemblyReferenceHandle)scope);
        }
        typeRefs = Rows(usedTypes.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)));
        memberRefs = Rows(usedMembers.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)));
        assemblyRefs = Rows(usedAssemblies.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)));
        var usedAssemblyNames = assemblyRefs.Keys.Select(handle => md.GetString(md.GetAssemblyReference(handle).Name)).ToHashSet(StringComparer.Ordinal);
        foreach (var alias in referenceAliases.Keys)
            if (!usedAssemblyNames.Contains(alias)) throw new Exception($"Dependency reference assembly '{alias}' is not used");
        foreach (var pair in emptyArrayScopes.OrderBy(pair => pair.Key))
        {
            string name = pair.Key switch { 0x05 => "Byte", 0x08 => "Int32", _ => throw new Exception("Unsupported empty-array element") };
            syntheticTypeRefs.Add((pair.Value, name));
            emptyArrayTypeRows.Add(pair.Key, checked((ushort)(typeRefs.Count + syntheticTypeRefs.Count)));
        }
        ValidateTransactions();
    }

    static Dictionary<T, ushort> Rows<T>(IEnumerable<T> handles) where T : struct
    {
        var result = new Dictionary<T, ushort>();
        foreach (var handle in handles) result.Add(handle, checked((ushort)(result.Count + 1)));
        return result;
    }

    string MethodName(MethodDefinition definition) =>
        (definition.Attributes & System.Reflection.MethodAttributes.MemberAccessMask) ==
        System.Reflection.MethodAttributes.Public
            ? md.GetString(definition.Name)
            : "_";

    public static void Write(string input, string output, string frameworkName, byte[] frameworkHash,
        string deviceAssemblyName, IReadOnlyDictionary<string, string> referenceAliases)
    {
        using var writer = new Mc04Writer(input, frameworkName, frameworkHash, deviceAssemblyName, referenceAliases);
        writer.Write(output);
    }

    public void Dispose()
    {
        pe.Dispose();
        file.Dispose();
    }

    void Write(string output)
    {
        if (typeDefs.Count is < 1 or > Mc04Schema.MaxTypeDefRows ||
            methods.Count is < 1 or > Mc04Schema.MaxMethodDefRows ||
            fields.Count > Mc04Schema.MaxFieldRows || TypeRefCount > Mc04Schema.MaxTypeRefRows ||
            memberRefs.Count > Mc04Schema.MaxMemberRefRows || assemblyRefs.Count > Mc04Schema.MaxAssemblyRefRows)
            throw new Exception("MC04 metadata row quota exceeded");

        var attributes = RuntimeAttributes()
            .OrderBy(item => item.Parent)
            .ThenBy(item => CustomAttributeType(md.GetCustomAttribute(item.Attribute).Constructor))
            .ThenBy(item => md.GetBlobBytes(md.GetCustomAttribute(item.Attribute).Value),
                Comparer<byte[]>.Create((left, right) => left.AsSpan().SequenceCompareTo(right)))
            .ThenBy(item => MetadataTokens.GetRowNumber(item.Attribute))
            .ToArray();
        if (attributes.Length > Mc04Schema.MaxCustomAttributeRows) throw new Exception("MC04 custom attribute quota exceeded");
        var codeOffsets = new Dictionary<MethodDefinitionHandle, uint>();
        using var code = new MemoryStream();
        using (var writer = new BinaryWriter(code, Encoding.UTF8, true))
        {
            foreach (var handle in md.MethodDefinitions)
            {
                var method = md.GetMethodDefinition(handle);
                if (method.RelativeVirtualAddress == 0) throw new Exception("MC04 requires method bodies");
                byte[] cil;
                try { cil = CompactCil(methodCode[handle]); }
                catch (Exception error)
                {
                    var owner = md.GetTypeDefinition(method.GetDeclaringType());
                    throw new Exception($"{md.GetString(owner.Name)}.{md.GetString(method.Name)}: {error.Message}");
                }
                var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                ushort locals = 0;
                if (!body.LocalSignature.IsNil)
                    locals = blobs.Add(RewriteSignature(md.GetBlobBytes(md.GetStandaloneSignature(body.LocalSignature).Signature)));
                codeOffsets.Add(handle, checked((uint)code.Position));
                byte flags = (byte)((transactionalMethods.Contains(handle) ? 1 : 0) |
                    (body.LocalVariablesInitialized ? 2 : 0));
                writer.Write(flags);
                writer.Write((byte)0);
                writer.Write(checked((ushort)body.MaxStack));
                writer.Write(checked((uint)cil.Length));
                writer.Write(locals);
                writer.Write((ushort)0);
                writer.Write(cil);
            }
        }

        PopulateHeaps(attributes);
        int stringWidth = strings.Length <= 256 ? 1 : 2;
        int blobWidth = blobs.Length <= 256 ? 1 : 2;
        var rowCounts = RowCounts(attributes.Length);
        using var tables = BuildTables(attributes, codeOffsets, rowCounts, stringWidth, blobWidth);
        ReadOnlyMemory<byte>[] sections =
        [
            Buffer(tables),
            strings.Bytes,
            blobs.Bytes,
            Buffer(code)
        ];
        const ushort headerSize = 56;
        uint fileSize = checked((uint)(headerSize + sections.Sum(section => section.Length)));
        var temporary = $"{output}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var assembly = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new BinaryWriter(assembly, Encoding.UTF8, true))
            {
                writer.Write("MC04"u8);
                writer.Write((byte)4); writer.Write((byte)0); writer.Write((ushort)0);
                writer.Write((byte)4); writer.Write((byte)2); writer.Write(headerSize); writer.Write(fileSize);
                uint offset = headerSize;
                for (byte index = 0; index < sections.Length; index++)
                {
                    writer.Write((byte)(index + 1)); writer.Write((byte)0);
                    writer.Write(offset); writer.Write(checked((uint)sections[index].Length));
                    offset = checked(offset + (uint)sections[index].Length);
                }
                foreach (var section in sections) writer.Write(section.Span);
            }
            File.Move(temporary, output, true);
        }
        catch
        {
            File.Delete(temporary);
            throw;
        }
    }

    static ReadOnlyMemory<byte> Buffer(MemoryStream stream) =>
        stream.GetBuffer().AsMemory(0, checked((int)stream.Length));

}

