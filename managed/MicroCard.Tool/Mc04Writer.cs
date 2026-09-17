using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

sealed class Mc04Writer : IDisposable
{
    readonly FileStream file;
    readonly PEReader pe;
    readonly MetadataReader md;
    readonly string frameworkName;
    readonly byte[] frameworkHash;
    readonly string deviceAssemblyName;
    readonly IReadOnlyDictionary<string, string> referenceAliases;
    readonly AssemblyReferenceHandle frameworkReference;
    readonly Dictionary<short, OpCode> opcodes = typeof(OpCodes).GetFields()
        .Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null)!)
        .ToDictionary(opcode => opcode.Value);
    readonly Dictionary<TypeDefinitionHandle, ushort> typeDefs;
    readonly Dictionary<TypeReferenceHandle, ushort> typeRefs;
    readonly Dictionary<FieldDefinitionHandle, ushort> fields;
    readonly Dictionary<MethodDefinitionHandle, ushort> methods;
    readonly Dictionary<MemberReferenceHandle, ushort> memberRefs;
    readonly Dictionary<AssemblyReferenceHandle, ushort> assemblyRefs;
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
            foreach (var token in CilTokens(body.GetILBytes()!))
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
            if (IsProjectedSystemCryptography(handle)) usedAssemblies.Add(frameworkReference);
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
                var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                if (body.ExceptionRegions.Length != 0) throw new Exception("MC04 exception handlers unsupported");
                byte[] cil;
                try { cil = CompactCil(body.GetILBytes()!); }
                catch (Exception error)
                {
                    var owner = md.GetTypeDefinition(method.GetDeclaringType());
                    throw new Exception($"{md.GetString(owner.Name)}.{md.GetString(method.Name)}: {error.Message}");
                }
                ushort locals = 0;
                if (!body.LocalSignature.IsNil)
                    locals = blobs.Add(RewriteSignature(md.GetBlobBytes(md.GetStandaloneSignature(body.LocalSignature).Signature)));
                codeOffsets.Add(handle, checked((uint)code.Position));
                byte flags = (byte)((HasAttribute(method.GetCustomAttributes(), "TransactionAttribute") ? 1 : 0) |
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

    Dictionary<byte, ushort> RowCounts(int attributeCount)
    {
        var rows = new Dictionary<byte, ushort>
        {
            [Mc04Schema.Module] = 1,
            [Mc04Schema.TypeDef] = checked((ushort)typeDefs.Count),
            [Mc04Schema.MethodDef] = checked((ushort)methods.Count),
            [Mc04Schema.Assembly] = 1,
        };
        if (TypeRefCount != 0) rows[Mc04Schema.TypeRef] = checked((ushort)TypeRefCount);
        if (fields.Count != 0) rows[Mc04Schema.Field] = checked((ushort)fields.Count);
        if (memberRefs.Count != 0) rows[Mc04Schema.MemberRef] = checked((ushort)memberRefs.Count);
        if (attributeCount != 0) rows[Mc04Schema.CustomAttribute] = checked((ushort)attributeCount);
        if (assemblyRefs.Count != 0) rows[Mc04Schema.AssemblyRef] = checked((ushort)assemblyRefs.Count);
        return rows;
    }

    void PopulateHeaps((ushort Parent, CustomAttributeHandle Attribute)[] attributes)
    {
        strings.Add(md.GetString(md.GetModuleDefinition().Name));
        foreach (var handle in typeRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle))) { strings.Add(TypeReferenceName(handle)); strings.Add(TypeReferenceNamespace(handle)); }
        foreach (var value in syntheticTypeRefs) { strings.Add(value.Name); strings.Add("System"); }
        foreach (var handle in md.TypeDefinitions) { var value = md.GetTypeDefinition(handle); strings.Add(md.GetString(value.Name)); strings.Add(md.GetString(value.Namespace)); }
        foreach (var handle in fields.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle))) { var value = md.GetFieldDefinition(handle); strings.Add("_"); blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))); }
        foreach (var handle in md.MethodDefinitions) { var value = md.GetMethodDefinition(handle); strings.Add(MethodName(value)); blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))); }
        foreach (var handle in memberRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle))) { var value = md.GetMemberReference(handle); strings.Add(MemberReferenceName(handle)); blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))); }
        foreach (var (_, handle) in attributes) blobs.Add(md.GetBlobBytes(md.GetCustomAttribute(handle).Value));
        strings.Add(deviceAssemblyName);
        foreach (var handle in assemblyRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)))
        {
            var value = md.GetAssemblyReference(handle);
            strings.Add(AssemblyReferenceName(value));
            strings.Add(md.GetString(value.Culture));
            blobs.Add(md.GetBlobBytes(value.PublicKeyOrToken));
            blobs.Add(AssemblyHash(value));
        }
    }

    MemoryStream BuildTables((ushort Parent, CustomAttributeHandle Attribute)[] attributes,
        Dictionary<MethodDefinitionHandle, uint> codeOffsets, Dictionary<byte, ushort> rows,
        int stringWidth, int blobWidth)
    {
        ulong valid = rows.Keys.Aggregate(0UL, (mask, table) => mask | 1UL << table);
        if ((valid & ~Mc04Schema.AllowedTables) != 0) throw new Exception("Unsupported MC04 table");
        var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        writer.Write((byte)2); writer.Write((byte)0);
        writer.Write((byte)((stringWidth == 2 ? 1 : 0) | (blobWidth == 2 ? 2 : 0)));
        writer.Write((byte)0); writer.Write(valid);
        foreach (var table in rows.OrderBy(pair => pair.Key)) writer.Write(table.Value);

        WriteIndex(writer, strings.Add(md.GetString(md.GetModuleDefinition().Name)), stringWidth);
        foreach (var handle in typeRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)))
        {
            var value = md.GetTypeReference(handle);
            writer.Write(ResolutionScope(IsProjectedSystemCryptography(handle) ? frameworkReference : value.ResolutionScope));
            WriteIndex(writer, strings.Add(TypeReferenceName(handle)), stringWidth);
            WriteIndex(writer, strings.Add(TypeReferenceNamespace(handle)), stringWidth);
        }
        foreach (var value in syntheticTypeRefs)
        {
            writer.Write(ResolutionScope(value.Scope));
            WriteIndex(writer, strings.Add(value.Name), stringWidth);
            WriteIndex(writer, strings.Add("System"), stringWidth);
        }
        ushort fieldStart = 1, methodStart = 1;
        foreach (var handle in md.TypeDefinitions)
        {
            var value = md.GetTypeDefinition(handle);
            writer.Write((uint)value.Attributes);
            WriteIndex(writer, strings.Add(md.GetString(value.Name)), stringWidth);
            WriteIndex(writer, strings.Add(md.GetString(value.Namespace)), stringWidth);
            writer.Write(TypeDefOrRef(value.BaseType, true));
            WriteIndex(writer, fieldStart, fields.Count <= 255 ? 1 : 2);
            WriteIndex(writer, methodStart, methods.Count <= 255 ? 1 : 2);
            fieldStart = checked((ushort)(fieldStart + value.GetFields().Count(fields.ContainsKey)));
            methodStart = checked((ushort)(methodStart + value.GetMethods().Count));
        }
        foreach (var handle in fields.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)))
        {
            var value = md.GetFieldDefinition(handle);
            writer.Write((ushort)value.Attributes);
            WriteIndex(writer, strings.Add("_"), stringWidth);
            WriteIndex(writer, blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))), blobWidth);
        }
        foreach (var handle in md.MethodDefinitions)
        {
            var value = md.GetMethodDefinition(handle);
            writer.Write(codeOffsets[handle]);
            writer.Write((ushort)value.ImplAttributes); writer.Write((ushort)value.Attributes);
            WriteIndex(writer, strings.Add(MethodName(value)), stringWidth);
            WriteIndex(writer, blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))), blobWidth);
        }
        foreach (var handle in memberRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)))
        {
            var value = md.GetMemberReference(handle);
            writer.Write(MemberRefParent(value.Parent));
            WriteIndex(writer, strings.Add(MemberReferenceName(handle)), stringWidth);
            WriteIndex(writer, blobs.Add(RewriteSignature(md.GetBlobBytes(value.Signature))), blobWidth);
        }
        foreach (var (parent, handle) in attributes)
        {
            var value = md.GetCustomAttribute(handle);
            writer.Write(parent); writer.Write(CustomAttributeType(value.Constructor));
            WriteIndex(writer, blobs.Add(md.GetBlobBytes(value.Value)), blobWidth);
        }
        var assembly = md.GetAssemblyDefinition();
        WriteVersion(writer, assembly.Version); writer.Write((uint)assembly.Flags);
        WriteIndex(writer, strings.Add(deviceAssemblyName), stringWidth);
        foreach (var handle in assemblyRefs.Keys.OrderBy(handle => MetadataTokens.GetRowNumber((EntityHandle)handle)))
        {
            var value = md.GetAssemblyReference(handle);
            WriteVersion(writer, value.Version); writer.Write((uint)value.Flags);
            WriteIndex(writer, blobs.Add(md.GetBlobBytes(value.PublicKeyOrToken)), blobWidth);
            WriteIndex(writer, strings.Add(AssemblyReferenceName(value)), stringWidth);
            WriteIndex(writer, strings.Add(md.GetString(value.Culture)), stringWidth);
            WriteIndex(writer, blobs.Add(AssemblyHash(value)), blobWidth);
        }
        return output;
    }

    byte[] AssemblyHash(AssemblyReference value) =>
        md.GetString(value.Name) == frameworkName ? frameworkHash : md.GetBlobBytes(value.HashValue);

    string AssemblyReferenceName(AssemblyReference value)
    {
        var name = md.GetString(value.Name);
        return referenceAliases.TryGetValue(name, out var replacement) ? replacement : name;
    }

    bool IsProjectedSystemCryptography(TypeReferenceHandle handle)
    {
        var type = md.GetTypeReference(handle);
        if (type.ResolutionScope.Kind != HandleKind.AssemblyReference ||
            md.GetString(type.Namespace) != "System.Security.Cryptography") return false;
        var name = md.GetString(type.Name);
        return name is "SHA256" or "RandomNumberGenerator" &&
               md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope).Name) ==
               "System.Security.Cryptography";
    }

    bool IsProjectedSystemCryptography(MemberReferenceHandle handle)
    {
        var member = md.GetMemberReference(handle);
        var signature = md.GetBlobBytes(member.Signature);
        if (member.Parent.Kind != HandleKind.TypeReference ||
            !IsProjectedSystemCryptography((TypeReferenceHandle)member.Parent)) return false;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (md.GetString(type.Name) == "SHA256")
            return md.GetString(member.Name) == "HashData" &&
                   signature.Length == 6 && signature[0] == 0x00 && signature[1] == 0x01 &&
                   signature[2] == 0x1d && signature[3] == 0x05 &&
                   signature[4] == 0x1d && signature[5] == 0x05;
        return md.GetString(member.Name) == "GetBytes" &&
               signature.Length == 5 && signature[0] == 0x00 && signature[1] == 0x01 &&
               signature[2] == 0x1d && signature[3] == 0x05 && signature[4] == 0x08;
    }

    string TypeReferenceName(TypeReferenceHandle handle) =>
        IsProjectedSystemCryptography(handle) ? "Cryptography" : md.GetString(md.GetTypeReference(handle).Name);

    string TypeReferenceNamespace(TypeReferenceHandle handle) =>
        IsProjectedSystemCryptography(handle) ? "MicroCard.Framework" : md.GetString(md.GetTypeReference(handle).Namespace);

    string MemberReferenceName(MemberReferenceHandle handle)
    {
        if (!IsProjectedSystemCryptography(handle)) return md.GetString(md.GetMemberReference(handle).Name);
        return md.GetString(md.GetTypeReference(
            (TypeReferenceHandle)md.GetMemberReference(handle).Parent).Name) == "SHA256"
            ? "Sha256" : "RandomBytes";
    }

    static void WriteVersion(BinaryWriter writer, Version version)
    {
        writer.Write(checked((ushort)version.Major)); writer.Write(checked((ushort)version.Minor));
        writer.Write(checked((ushort)Math.Max(version.Build, 0))); writer.Write(checked((ushort)Math.Max(version.Revision, 0)));
    }

    int TypeRefCount => checked(typeRefs.Count + syntheticTypeRefs.Count);

    bool TryGetEmptyArrayElement(EntityHandle handle, out byte element, out EntityHandle scope)
    {
        element = 0;
        scope = default;
        if (handle.Kind != HandleKind.MethodSpecification) return false;
        var specification = md.GetMethodSpecification((MethodSpecificationHandle)handle);
        byte[] instantiation = md.GetBlobBytes(specification.Signature);
        if (instantiation.Length != 3 || instantiation[0] != 0x0a || instantiation[1] != 1 ||
            instantiation[2] is not (0x05 or 0x08) || specification.Method.Kind != HandleKind.MemberReference)
            return false;
        var member = md.GetMemberReference((MemberReferenceHandle)specification.Method);
        if (md.GetString(member.Name) != "Empty" || member.Parent.Kind != HandleKind.TypeReference ||
            !md.GetBlobBytes(member.Signature).AsSpan().SequenceEqual(new byte[] { 0x10, 0x01, 0x00, 0x1d, 0x1e, 0x00 }))
            return false;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (md.GetString(type.Namespace) != "System" || md.GetString(type.Name) != "Array" ||
            type.ResolutionScope.Kind != HandleKind.AssemblyReference)
            return false;
        var assembly = md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope);
        if (md.GetString(assembly.Name) != "System.Runtime" ||
            !md.GetBlobBytes(assembly.PublicKeyOrToken).AsSpan()
                .SequenceEqual(new byte[] { 0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a }))
            return false;
        element = instantiation[2];
        scope = type.ResolutionScope;
        return true;
    }

    static void WriteIndex(BinaryWriter writer, ushort value, int width)
    {
        if (width == 1) writer.Write(checked((byte)value)); else if (width == 2) writer.Write(value); else throw new Exception("Invalid index width");
    }

    ushort ResolutionScope(EntityHandle handle) => handle.Kind switch
    {
        HandleKind.ModuleDefinition => (ushort)(1 << 2),
        HandleKind.AssemblyReference => checked((ushort)(assemblyRefs[(AssemblyReferenceHandle)handle] << 2 | 2)),
        HandleKind.TypeReference => checked((ushort)(typeRefs[(TypeReferenceHandle)handle] << 2 | 3)),
        _ => throw new Exception("Unsupported TypeRef resolution scope")
    };

    ushort TypeDefOrRef(EntityHandle handle, bool nil = false)
    {
        if (handle.IsNil && nil) return 0;
        return handle.Kind switch
        {
            HandleKind.TypeDefinition => checked((ushort)(typeDefs[(TypeDefinitionHandle)handle] << 2)),
            HandleKind.TypeReference => checked((ushort)(typeRefs[(TypeReferenceHandle)handle] << 2 | 1)),
            _ => throw new Exception("Unsupported TypeDefOrRef")
        };
    }

    ushort MemberRefParent(EntityHandle handle) => handle.Kind switch
    {
        HandleKind.TypeDefinition => checked((ushort)(typeDefs[(TypeDefinitionHandle)handle] << 3)),
        HandleKind.TypeReference => checked((ushort)(typeRefs[(TypeReferenceHandle)handle] << 3 | 1)),
        HandleKind.MethodDefinition => checked((ushort)(methods[(MethodDefinitionHandle)handle] << 3 | 3)),
        _ => throw new Exception("Unsupported MemberRef parent")
    };

    ushort CustomAttributeType(EntityHandle handle) => handle.Kind switch
    {
        HandleKind.MethodDefinition => checked((ushort)(methods[(MethodDefinitionHandle)handle] << 3 | 2)),
        HandleKind.MemberReference => checked((ushort)(memberRefs[(MemberReferenceHandle)handle] << 3 | 3)),
        _ => throw new Exception("Unsupported custom attribute constructor")
    };

    IEnumerable<(ushort Parent, CustomAttributeHandle Attribute)> RuntimeAttributes()
    {
        foreach (var handle in md.GetAssemblyDefinition().GetCustomAttributes())
            if (IsRuntimeAttribute(handle)) yield return (checked((ushort)(1 << 5 | 14)), handle);
        foreach (var type in md.TypeDefinitions)
            foreach (var handle in md.GetTypeDefinition(type).GetCustomAttributes())
                if (IsRuntimeAttribute(handle)) yield return (checked((ushort)(typeDefs[type] << 5 | 3)), handle);
        foreach (var method in md.MethodDefinitions)
            foreach (var handle in md.GetMethodDefinition(method).GetCustomAttributes())
                if (IsRuntimeAttribute(handle)) yield return (checked((ushort)(methods[method] << 5)), handle);
        foreach (var field in fields.Keys)
            foreach (var handle in md.GetFieldDefinition(field).GetCustomAttributes())
                if (IsRuntimeAttribute(handle)) yield return (checked((ushort)(fields[field] << 5 | 1)), handle);
    }

    bool HasAttribute(CustomAttributeHandleCollection attributes, string name) =>
        attributes.Any(handle => IsFrameworkAttribute(handle) && AttributeName(handle) == name);

    bool IsFrameworkAttribute(CustomAttributeHandle handle) => AttributeName(handle) is not null;
    bool IsRuntimeAttribute(CustomAttributeHandle handle) => AttributeName(handle) is
        "AssemblyAttribute" or "InstallAttribute" or "SelectAttribute" or "DeselectAttribute" or
        "ProcessAttribute" or "UninstallAttribute" or "TransactionAttribute";
    string? AttributeName(CustomAttributeHandle handle)
    {
        var value = md.GetCustomAttribute(handle);
        if (value.Constructor.Kind != HandleKind.MemberReference) return null;
        var member = md.GetMemberReference((MemberReferenceHandle)value.Constructor);
        if (member.Parent.Kind != HandleKind.TypeReference) return null;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (type.ResolutionScope.Kind != HandleKind.AssemblyReference) return null;
        var assembly = md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope);
        return md.GetString(assembly.Name) == frameworkName && md.GetString(type.Namespace) == "MicroCard.Framework"
            ? md.GetString(type.Name) : null;
    }

    void CollectSignature(byte[] signature, HashSet<TypeReferenceHandle> usedTypes) =>
        TransformSignature(signature, usedTypes, false);

    byte[] RewriteSignature(byte[] signature) => TransformSignature(signature, null, true);

    byte[] TransformSignature(byte[] input, HashSet<TypeReferenceHandle>? usedTypes, bool remap)
    {
        int cursor = 0;
        using var output = new MemoryStream();
        uint Compressed()
        {
            byte first = input[cursor++];
            if (first < 0x80) return first;
            if (first < 0xc0) return checked((uint)((first & 0x3f) << 8 | input[cursor++]));
            if (first < 0xe0)
            {
                uint value = checked((uint)(first & 0x1f) << 24);
                value |= checked((uint)input[cursor++] << 16);
                value |= checked((uint)input[cursor++] << 8);
                return value | input[cursor++];
            }
            throw new Exception("Invalid compressed signature integer");
        }
        void WriteCompressed(uint value)
        {
            if (value <= 0x7f) output.WriteByte((byte)value);
            else if (value <= 0x3fff) { output.WriteByte((byte)(0x80 | value >> 8)); output.WriteByte((byte)value); }
            else if (value <= 0x1fffffff)
            {
                output.WriteByte((byte)(0xc0 | value >> 24)); output.WriteByte((byte)(value >> 16));
                output.WriteByte((byte)(value >> 8)); output.WriteByte((byte)value);
            }
            else throw new Exception("Signature token exceeds ECMA compressed integer range");
        }
        void Type()
        {
            byte kind = input[cursor++]; output.WriteByte(kind);
            if (kind == 0x1d) { Type(); return; }
            if (kind is 0x11 or 0x12)
            {
                uint coded = Compressed(); uint tag = coded & 3; uint row = coded >> 2;
                EntityHandle handle = tag switch
                {
                    0 when row != 0 => MetadataTokens.TypeDefinitionHandle(checked((int)row)),
                    1 when row != 0 => MetadataTokens.TypeReferenceHandle(checked((int)row)),
                    _ => throw new Exception("Unsupported signature TypeDefOrRef")
                };
                if (handle.Kind == HandleKind.TypeReference) usedTypes?.Add((TypeReferenceHandle)handle);
                uint rewritten = handle.Kind switch
                {
                    HandleKind.TypeDefinition => checked((uint)typeDefs[(TypeDefinitionHandle)handle] << 2),
                    HandleKind.TypeReference when remap => checked((uint)typeRefs[(TypeReferenceHandle)handle] << 2 | 1),
                    HandleKind.TypeReference => coded,
                    _ => throw new Exception("Unsupported signature type")
                };
                WriteCompressed(rewritten); return;
            }
            if (kind is not (0x01 or 0x02 or 0x04 or 0x05 or 0x06 or 0x07 or 0x08 or 0x09 or 0x0e or 0x1c))
                throw new Exception($"Unsupported signature element 0x{kind:X2}");
        }
        byte calling = input[cursor++]; output.WriteByte(calling);
        int kind = calling & 0x0f;
        if ((calling & 0x10) != 0) throw new Exception("Generic signatures unsupported");
        if (kind == 6) Type();
        else if (kind == 7)
        {
            uint count = Compressed();
            if (count > 64) throw new Exception("MC04 local-variable quota exceeded");
            WriteCompressed(count); for (uint i = 0; i < count; i++) Type();
        }
        else
        {
            if (calling is not (0x00 or 0x20)) throw new Exception("Unsupported signature calling convention or flags");
            uint count = Compressed(); WriteCompressed(count); Type(); for (uint i = 0; i < count; i++) Type();
        }
        if (cursor != input.Length) throw new Exception("Trailing signature bytes");
        return output.ToArray();
    }

    IEnumerable<EntityHandle> CilTokens(byte[] input)
    {
        int pc = 0;
        while (pc < input.Length)
        {
            byte first = input[pc++]; short value = first;
            if (first == 0xfe) value = (short)(0xfe00 | input[pc++]);
            if (!opcodes.TryGetValue(value, out var opcode)) throw new Exception("Unknown CIL opcode");
            switch (opcode.OperandType)
            {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI: case OperandType.ShortInlineVar: case OperandType.ShortInlineBrTarget: pc += 1; break;
                case OperandType.InlineI: case OperandType.InlineBrTarget: pc += 4; break;
                case OperandType.InlineSwitch:
                    int count = BitConverter.ToInt32(input, pc); pc += 4 + checked(count * 4); break;
                case OperandType.InlineMethod: case OperandType.InlineField: case OperandType.InlineType:
                    yield return MetadataTokens.EntityHandle(BitConverter.ToInt32(input, pc)); pc += 4; break;
                default: throw new Exception($"Unsupported MC04 CIL operand {opcode.OperandType}");
            }
            if (pc > input.Length) throw new Exception("Truncated CIL operand");
        }
    }

    void ValidateTransactions()
    {
        var effects = new Dictionary<MethodDefinitionHandle, bool>();
        var active = new HashSet<MethodDefinitionHandle>();
        var controls = new Dictionary<MethodDefinitionHandle, bool>();
        var activeControls = new HashSet<MethodDefinitionHandle>();

        bool ReachesIrreversibleOutput(MethodDefinitionHandle handle)
        {
            if (effects.TryGetValue(handle, out bool known)) return known;
            if (!active.Add(handle)) return false;
            var definition = md.GetMethodDefinition(handle);
            var body = pe.GetMethodBody(definition.RelativeVirtualAddress);
            bool effect = false;
            foreach (var target in CilCalls(body.GetILBytes()!))
            {
                if (target.Kind == HandleKind.MethodDefinition)
                    effect |= ReachesIrreversibleOutput((MethodDefinitionHandle)target);
                else if (target.Kind == HandleKind.MemberReference)
                    effect |= IsIrreversibleOutput((MemberReferenceHandle)target);
                if (effect) break;
            }
            active.Remove(handle);
            effects[handle] = effect;
            return effect;
        }

        bool ReachesExplicitControl(MethodDefinitionHandle handle)
        {
            if (controls.TryGetValue(handle, out bool known)) return known;
            if (!activeControls.Add(handle)) return false;
            var definition = md.GetMethodDefinition(handle);
            var body = pe.GetMethodBody(definition.RelativeVirtualAddress);
            bool control = false;
            foreach (var target in CilCalls(body.GetILBytes()!))
            {
                if (target.Kind == HandleKind.MethodDefinition)
                    control |= ReachesExplicitControl((MethodDefinitionHandle)target);
                else if (target.Kind == HandleKind.MemberReference)
                    control |= IsExplicitTransactionControl((MemberReferenceHandle)target);
                if (control) break;
            }
            activeControls.Remove(handle);
            controls[handle] = control;
            return control;
        }

        foreach (var handle in md.MethodDefinitions)
            if ((HasAttribute(md.GetMethodDefinition(handle).GetCustomAttributes(), "TransactionAttribute") ||
                 ReachesExplicitControl(handle)) &&
                ReachesIrreversibleOutput(handle))
                throw new Exception("Transactional method reaches irreversible Hardware.Write");
    }

    bool IsExplicitTransactionControl(MemberReferenceHandle handle)
    {
        var member = md.GetMemberReference(handle);
        string name = md.GetString(member.Name);
        if (name is not ("BeginTransaction" or "CommitTransaction" or "AbortTransaction") ||
            member.Parent.Kind != HandleKind.TypeReference)
            return false;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (md.GetString(type.Name) != "DomainStorage" ||
            md.GetString(type.Namespace) != "MicroCard.Framework" ||
            type.ResolutionScope.Kind != HandleKind.AssemblyReference)
            return false;
        return md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope).Name) == frameworkName;
    }

    bool IsIrreversibleOutput(MemberReferenceHandle handle)
    {
        var member = md.GetMemberReference(handle);
        if (md.GetString(member.Name) != "Write" || member.Parent.Kind != HandleKind.TypeReference)
            return false;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (md.GetString(type.Name) != "Hardware" ||
            md.GetString(type.Namespace) != "MicroCard.Framework" ||
            type.ResolutionScope.Kind != HandleKind.AssemblyReference)
            return false;
        return md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope).Name) == frameworkName;
    }

    IEnumerable<EntityHandle> CilCalls(byte[] input)
    {
        int pc = 0;
        while (pc < input.Length)
        {
            byte first = input[pc++]; short value = first;
            if (first == 0xfe) value = (short)(0xfe00 | input[pc++]);
            if (!opcodes.TryGetValue(value, out var opcode)) throw new Exception("Unknown CIL opcode");
            switch (opcode.OperandType)
            {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI: case OperandType.ShortInlineVar: case OperandType.ShortInlineBrTarget: pc += 1; break;
                case OperandType.InlineI: case OperandType.InlineBrTarget: pc += 4; break;
                case OperandType.InlineSwitch:
                    int count = BitConverter.ToInt32(input, pc); pc += 4 + checked(count * 4); break;
                case OperandType.InlineMethod:
                    var target = MetadataTokens.EntityHandle(BitConverter.ToInt32(input, pc)); pc += 4;
                    if (value is 0x0028 or 0x006f or 0x0073) yield return target;
                    break;
                case OperandType.InlineField: case OperandType.InlineType: pc += 4; break;
                default: throw new Exception($"Unsupported MC04 CIL operand {opcode.OperandType}");
            }
            if (pc > input.Length) throw new Exception("Truncated CIL operand");
        }
    }

    byte[] CompactCil(byte[] input)
    {
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output);
        var offsets = new Dictionary<int, int>(); var patches = new List<(int Position, int Target, int Base, int Width)>();
        int pc = 0;
        while (pc < input.Length)
        {
            int start = pc; offsets[start] = checked((int)output.Position);
            byte first = input[pc++]; byte second = 0; short value = first;
            if (first == 0xfe) { second = input[pc++]; value = (short)(0xfe00 | second); }
            if (!opcodes.TryGetValue(value, out var opcode)) throw new Exception("Unknown CIL opcode");
            if (!Mc04Opcodes.IsAllowed(value)) throw new Exception($"CIL opcode {opcode.Name} is outside the MC04 profile");
            int Read4() { int result = BitConverter.ToInt32(input, pc); pc += 4; return result; }
            if (value == OpCodes.Call.Value && opcode.OperandType == OperandType.InlineMethod)
            {
                var handle = MetadataTokens.EntityHandle(BitConverter.ToInt32(input, pc));
                if (TryGetEmptyArrayElement(handle, out byte element, out _))
                {
                    pc += 4;
                    writer.Write((byte)OpCodes.Ldc_I4_0.Value);
                    writer.Write((byte)OpCodes.Newarr.Value);
                    writer.Write(Mc04Schema.TypeRef);
                    writer.Write(emptyArrayTypeRows[element]);
                    continue;
                }
            }
            writer.Write(first);
            if (first == 0xfe) writer.Write(second);
            switch (opcode.OperandType)
            {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI: case OperandType.ShortInlineVar: writer.Write(input[pc++]); break;
                case OperandType.InlineI: writer.Write(Read4()); break;
                case OperandType.ShortInlineBrTarget:
                {
                    int target = pc + 1 + (sbyte)input[pc++]; int position = checked((int)output.Position);
                    writer.Write((byte)0); patches.Add((position, target, position + 1, 1)); break;
                }
                case OperandType.InlineBrTarget:
                {
                    int relative = Read4(); int target = pc + relative; int position = checked((int)output.Position);
                    writer.Write(0); patches.Add((position, target, position + 4, 4)); break;
                }
                case OperandType.InlineSwitch:
                {
                    int count = Read4(); if (count < 0 || count > 256) throw new Exception("Switch quota");
                    var relatives = new int[count]; for (int i = 0; i < count; i++) relatives[i] = Read4();
                    writer.Write(count); int firstPatch = checked((int)output.Position);
                    for (int i = 0; i < count; i++) writer.Write(0);
                    int newBase = checked((int)output.Position);
                    for (int i = 0; i < count; i++) patches.Add((firstPatch + i * 4, pc + relatives[i], newBase, 4));
                    break;
                }
                case OperandType.InlineMethod: case OperandType.InlineField: case OperandType.InlineType:
                {
                    var handle = MetadataTokens.EntityHandle(Read4());
                    var (table, row) = CompactToken(handle); writer.Write(table); writer.Write(row); break;
                }
                default: throw new Exception($"Unsupported MC04 CIL operand {opcode.OperandType}");
            }
        }
        var bytes = output.ToArray();
        foreach (var patch in patches)
        {
            if (!offsets.TryGetValue(patch.Target, out int target)) throw new Exception("Branch target is not an instruction");
            int relative = checked(target - patch.Base);
            if (patch.Width == 1) bytes[patch.Position] = unchecked((byte)checked((sbyte)relative));
            else BitConverter.GetBytes(relative).CopyTo(bytes, patch.Position);
        }
        return bytes;
    }

    (byte Table, ushort Row) CompactToken(EntityHandle handle) => handle.Kind switch
    {
        HandleKind.TypeDefinition => (Mc04Schema.TypeDef, typeDefs[(TypeDefinitionHandle)handle]),
        HandleKind.TypeReference => (Mc04Schema.TypeRef, typeRefs[(TypeReferenceHandle)handle]),
        HandleKind.FieldDefinition => (Mc04Schema.Field, fields[(FieldDefinitionHandle)handle]),
        HandleKind.MethodDefinition => (Mc04Schema.MethodDef, methods[(MethodDefinitionHandle)handle]),
        HandleKind.MemberReference => (Mc04Schema.MemberRef, memberRefs[(MemberReferenceHandle)handle]),
        _ => throw new Exception($"Unsupported MC04 metadata token {handle.Kind}")
    };
}

sealed class StringHeap
{
    readonly MemoryStream data = new();
    readonly Dictionary<string, ushort> offsets = new(StringComparer.Ordinal) { [""] = 0 };
    public StringHeap() => data.WriteByte(0);
    public int Length => checked((int)data.Length);
    public ushort Add(string value)
    {
        if (offsets.TryGetValue(value, out var offset)) return offset;
        if (value.Contains('\0')) throw new Exception("NUL in metadata string");
        var encoded = Encoding.UTF8.GetBytes(value); offset = checked((ushort)data.Position);
        data.Write(encoded); data.WriteByte(0); offsets.Add(value, offset); return offset;
    }
    public ReadOnlyMemory<byte> Bytes => data.GetBuffer().AsMemory(0, Length);
}

sealed class BlobHeap
{
    readonly MemoryStream data = new();
    readonly Dictionary<string, ushort> offsets = new(StringComparer.Ordinal);
    public BlobHeap() => data.WriteByte(0);
    public int Length => checked((int)data.Length);
    public ushort Add(byte[] value)
    {
        var key = Convert.ToHexString(value); if (offsets.TryGetValue(key, out var offset)) return offset;
        if (value.Length > 16383) throw new Exception("MC04 blob quota"); offset = checked((ushort)data.Position);
        if (value.Length < 128) data.WriteByte((byte)value.Length);
        else { data.WriteByte((byte)(0x80 | value.Length >> 8)); data.WriteByte((byte)value.Length); }
        data.Write(value); offsets.Add(key, offset); return offset;
    }
    public ReadOnlyMemory<byte> Bytes => data.GetBuffer().AsMemory(0, Length);
}
