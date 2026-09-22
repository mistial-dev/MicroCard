using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Collections.Immutable;
using System.Text.Json;
using MicroCard.Build;
// ECMA-335, 6th ed., II.22 metadata; III.3 instructions. Input assembly code is never executed here.
if (args.Length != 2) { Console.Error.WriteLine("usage: MicroCard.Tool ASSEMBLY OUTPUT_PREFIX"); return 2; }
try { new Compiler(args[0]).WriteMc04(args[1]); return 0; }
catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
sealed class Types : ISignatureTypeProvider<string, object?>, ICustomAttributeTypeProvider<string>
{
    public string GetPrimitiveType(PrimitiveTypeCode c) => c switch { PrimitiveTypeCode.Void => "void", PrimitiveTypeCode.Boolean => "bool", PrimitiveTypeCode.Int32 => "int32", PrimitiveTypeCode.Byte => "byte", _ => c.ToString() };
    public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte k) { var t = r.GetTypeDefinition(h); return "ref:" + r.GetString(t.Namespace) + "." + r.GetString(t.Name); }
    public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte k) { var t = r.GetTypeReference(h); return "ref:" + r.GetString(t.Namespace) + "." + r.GetString(t.Name); }
    public string GetTypeFromSpecification(MetadataReader r, object? c, TypeSpecificationHandle h, byte k) => throw new NotSupportedException("Type specification");
    public string GetSZArrayType(string t) => t + "[]";
    public string GetArrayType(string t, ArrayShape s) => throw new NotSupportedException();
    public string GetByReferenceType(string t) => throw new NotSupportedException("By-reference signatures unsupported"); public string GetPointerType(string t) => throw new NotSupportedException();
    public string GetGenericInstantiation(string t, ImmutableArray<string> a) => throw new NotSupportedException();
    public string GetGenericMethodParameter(object? c, int i) => throw new NotSupportedException(); public string GetGenericTypeParameter(object? c, int i) => throw new NotSupportedException();
    public string GetModifiedType(string m, string t, bool r) => throw new NotSupportedException("Modified signatures unsupported"); public string GetPinnedType(string t) => throw new NotSupportedException(); public string GetFunctionPointerType(MethodSignature<string> s) => throw new NotSupportedException();
    public PrimitiveTypeCode GetUnderlyingEnumType(string type) => PrimitiveTypeCode.Int32;
    public bool IsSystemType(string type) => type == "ref:System.Type";
    public string GetSystemType() => "ref:System.Type";
    public string GetTypeFromSerializedName(string name) => name;
}
sealed class Compiler : IDisposable
{
    readonly string input; readonly FileStream file; readonly PEReader pe; readonly MetadataReader md; readonly Types types = new();
    readonly Dictionary<MethodDefinitionHandle, int> ids = new(); readonly List<object> entry_points = new(); readonly SortedSet<int> caps = new();
    readonly string frameworkName = Mc04Abi.FrameworkAssembly;
    readonly byte[] frameworkHash = Convert.FromHexString(Mc04Abi.FrameworkIdentitySha256);
    readonly string deviceAssemblyName;
    readonly DependencyDeclaration[] dependencies;
    readonly object[] storage;

    sealed record DependencyDeclaration(string Name, string ReferenceName, bool HasExplicitReference, object Manifest);

    public Compiler(string input)
    {
        this.input = input;
        file = File.OpenRead(input); pe = new(file); md = pe.GetMetadataReader();
        deviceAssemblyName = DeviceAssemblyName();
        dependencies = Dependencies(deviceAssemblyName);
        storage = StorageSchema();
        if (md.TypeDefinitions.Any(h => !md.GetTypeDefinition(h).GetDeclaringType().IsNil))
            throw new Exception("Nested type unsupported");
        if (md.TypeDefinitions.Any(h => md.GetTypeDefinition(h).GetInterfaceImplementations().Count != 0))
            throw new Exception("Interfaces unsupported");
        const System.Reflection.TypeAttributes supportedTypeAttributes = System.Reflection.TypeAttributes.Public | System.Reflection.TypeAttributes.Abstract | System.Reflection.TypeAttributes.Sealed | System.Reflection.TypeAttributes.BeforeFieldInit;
        foreach (var h in md.TypeDefinitions) { var t = md.GetTypeDefinition(h); var name = md.GetString(t.Name); if (name == "<Module>") { if (t.Attributes != 0 || !t.BaseType.IsNil) throw new Exception("Unsupported module type"); continue; } if ((t.Attributes & ~supportedTypeAttributes) != 0 || (t.Attributes & System.Reflection.TypeAttributes.Sealed) == 0) throw new Exception("Unsupported type flags"); if (t.BaseType.Kind != HandleKind.TypeReference) throw new Exception("Unsupported base type"); var baseType = md.GetTypeReference((TypeReferenceHandle)t.BaseType); if (md.GetString(baseType.Name) != "Object" || md.GetString(baseType.Namespace) != "System" || baseType.ResolutionScope.Kind != HandleKind.AssemblyReference) throw new Exception("Unsupported base type"); }
        const System.Reflection.FieldAttributes supportedFieldAttributes = System.Reflection.FieldAttributes.FieldAccessMask | System.Reflection.FieldAttributes.InitOnly;
        foreach (var h in md.FieldDefinitions) { var f = md.GetFieldDefinition(h); var signature = md.GetBlobBytes(f.Signature); if (signature.Length != 2 || signature[0] != 0x06 || signature[1] != 0x08) throw new Exception("Only Int32 fields and constants supported"); if ((f.Attributes & System.Reflection.FieldAttributes.Literal) != 0) continue; if ((f.Attributes & ~supportedFieldAttributes) != 0) throw new Exception("Unsupported field flags"); }
        const System.Reflection.MethodAttributes supportedMethodAttributes = System.Reflection.MethodAttributes.MemberAccessMask | System.Reflection.MethodAttributes.Static | System.Reflection.MethodAttributes.HideBySig | System.Reflection.MethodAttributes.SpecialName | System.Reflection.MethodAttributes.RTSpecialName;
        foreach (var h in md.MethodDefinitions) { var m = md.GetMethodDefinition(h); var owner = md.GetTypeDefinition(m.GetDeclaringType()); if (owner.GetGenericParameters().Count != 0) throw new Exception("Generic type"); if ((m.Attributes & System.Reflection.MethodAttributes.Static) == 0 && (owner.Attributes & System.Reflection.TypeAttributes.Sealed) == 0) throw new Exception("Only sealed objects supported"); if ((m.Attributes & ~supportedMethodAttributes) != 0 || m.ImplAttributes != 0) throw new Exception("Unsupported method flags"); if (md.GetString(m.Name) == ".cctor") throw new Exception("Static constructor unsupported"); if (m.GetGenericParameters().Count != 0 || m.RelativeVirtualAddress == 0) throw new Exception("Unsupported method"); if (m.DecodeSignature(types, null).ParameterTypes.Length > 32) throw new Exception("Method parameter quota exceeded"); ids[h] = ids.Count; }
    }
    string Attr(CustomAttribute a) { if (a.Constructor.Kind != HandleKind.MemberReference) return ""; var m = md.GetMemberReference((MemberReferenceHandle)a.Constructor); if (m.Parent.Kind != HandleKind.TypeReference) return ""; var t = md.GetTypeReference((TypeReferenceHandle)m.Parent); if (t.ResolutionScope.Kind != HandleKind.AssemblyReference || md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)t.ResolutionScope).Name) != frameworkName || md.GetString(t.Namespace) != "MicroCard.Framework") return ""; return md.GetString(t.Name); }
    int[] Hex32(string? value, string field) { if (value is null || value.Length != 64) throw new Exception($"{field} must be 32 bytes of hexadecimal"); try { return Convert.FromHexString(value).Select(b => (int)b).ToArray(); } catch (FormatException) { throw new Exception($"{field} must be 32 bytes of hexadecimal"); } }
    object ExportPolicy()
    {
        var attributes = md.GetAssemblyDefinition().GetCustomAttributes().Select(md.GetCustomAttribute).Where(a => Attr(a) == "DependencyExportAttribute").ToArray();
        if (attributes.Length == 0) return new { access = 0, key = (int[]?)null };
        if (attributes.Length != 1) throw new Exception("Duplicate dependency export policy");
        var value = attributes[0].DecodeValue(types);
        if (value.FixedArguments.Length != 1) throw new Exception("Invalid dependency export policy");
        if (value.FixedArguments[0].Value is string key) return new { access = 3, key = (int[]?)Hex32(key, "Export key") };
        var access = Convert.ToInt32(value.FixedArguments[0].Value);
        if (access is not (1 or 2)) throw new Exception("Export policy must be Any or SameSigner");
        return new { access, key = (int[]?)null };
    }
    string DeviceAssemblyName()
    {
        var compiledName = md.GetString(md.GetAssemblyDefinition().Name);
        var attributes = md.GetAssemblyDefinition().GetCustomAttributes().Select(md.GetCustomAttribute)
            .Where(a => Attr(a) == "DeviceAssemblyIdentityAttribute").ToArray();
        if (attributes.Length == 0)
        {
            if (!EmbeddedIdentifier.IsValid(compiledName) || compiledName is "MicroCard.Framework" or "System.Runtime")
                throw new Exception("Device assembly identity must use the embedded identifier grammar");
            return compiledName;
        }
        if (attributes.Length != 1) throw new Exception("Duplicate device assembly identity");
        var value = attributes[0].DecodeValue(types);
        if (value.FixedArguments.Length != 1 || value.FixedArguments[0].Value is not string name ||
            !EmbeddedIdentifier.IsValid(name) || name is "MicroCard.Framework" or "System.Runtime")
            throw new Exception("Device assembly identity must use the embedded identifier grammar");
        return name;
    }
    DependencyDeclaration[] Dependencies(string assembly)
    {
        var result = new List<DependencyDeclaration>();
        foreach (var attribute in md.GetAssemblyDefinition().GetCustomAttributes().Select(md.GetCustomAttribute).Where(a => Attr(a) == "DependencyAttribute"))
        {
            if (result.Count >= 16) throw new Exception("Dependency quota exceeded");
            var value = attribute.DecodeValue(types);
            if (value.FixedArguments.Length != 2 || value.FixedArguments[0].Value is not string name || value.FixedArguments[1].Value is not string constraint || !EmbeddedIdentifier.IsValid(name) || name == assembly || name is "MicroCard.Framework" or "System.Runtime") throw new Exception("Invalid dependency declaration");
            uint packageVersion = 0; int[]? digest = null; int[]? signer = null; int scope = 2; string? referenceName = null;
            foreach (var named in value.NamedArguments)
            {
                if (named.Name == "ReferenceAssembly") referenceName = (string?)named.Value;
                else if (named.Name == "PackageVersion") packageVersion = Convert.ToUInt32(named.Value);
                else if (named.Name == "PackageDigestHex") digest = Hex32((string?)named.Value, "Package digest");
                else if (named.Name == "SignerPublicKeyHex") signer = Hex32((string?)named.Value, "Signer key");
                else if (named.Name == "Scope") scope = Convert.ToInt32(named.Value);
            }
            var explicitReference = referenceName is not null;
            referenceName ??= name;
            var compiledName = md.GetString(md.GetAssemblyDefinition().Name);
            if (referenceName.Length is < 1 or > 64 || referenceName == compiledName ||
                referenceName is "MicroCard.Framework" or "System.Runtime")
                throw new Exception("Dependency reference assembly is invalid or reserved");
            if (scope is < 0 or > 2) throw new Exception("Invalid dependency scope");
            var ranges = VersionConstraint.Normalize(constraint).Select(range => new { min = range.Minimum?.ToArray(), min_inclusive = range.MinimumInclusive, max = range.Maximum?.ToArray(), max_inclusive = range.MaximumInclusive }).ToArray();
            result.Add(new(name, referenceName, explicitReference, new { assembly = name, ranges, package_version = packageVersion, signer, digest, scope }));
        }
        var ordered = result.OrderBy(item => item.Name, StringComparer.Ordinal).ThenBy(item => item.ReferenceName, StringComparer.Ordinal).ToArray();
        for (var i = 1; i < ordered.Length; i++) if (ordered[i - 1].Name == ordered[i].Name) throw new Exception("Duplicate dependency");
        var aliases = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dependency in ordered) if (!aliases.Add(dependency.ReferenceName)) throw new Exception("Duplicate dependency reference assembly");
        return ordered;
    }
    object[] StorageSchema()
    {
        var declarations = new List<(int Key, int Kind, int MaxBytes)>();
        foreach (var attribute in md.GetAssemblyDefinition().GetCustomAttributes().Select(md.GetCustomAttribute)
                     .Where(a => Attr(a) is "PersistentInt32Attribute" or "PersistentBytesAttribute"))
        {
            if (declarations.Count >= 64) throw new Exception("Persistent storage declaration quota exceeded");
            var name = Attr(attribute);
            var value = attribute.DecodeValue(types);
            if (value.FixedArguments.Length == 0) throw new Exception("Invalid persistent storage declaration");
            var key = Convert.ToInt32(value.FixedArguments[0].Value);
            if (key < 0) throw new Exception("Persistent storage keys must be non-negative");
            var kind = name == "PersistentInt32Attribute" ? 1 : 2;
            var maxBytes = 0;
            if (kind == 1)
            {
                if (value.FixedArguments.Length != 1) throw new Exception("Invalid persistent Int32 declaration");
            }
            else
            {
                if (value.FixedArguments.Length != 2) throw new Exception("Invalid persistent byte declaration");
                maxBytes = Convert.ToInt32(value.FixedArguments[1].Value);
                if (maxBytes is < 1 or > 2048) throw new Exception("Persistent byte maximum must be from 1 through 2048");
            }
            declarations.Add((key, kind, maxBytes));
        }
        var ordered = declarations.OrderBy(item => item.Key).ToArray();
        for (var i = 1; i < ordered.Length; i++)
            if (ordered[i - 1].Key == ordered[i].Key) throw new Exception("Duplicate persistent storage key");
        return ordered.Select(item => (object)new { key = item.Key, kind = item.Kind, max_bytes = item.MaxBytes }).ToArray();
    }
    void CollectMc04Manifest()
    {
        foreach (var handle in md.MemberReferences)
        {
            var member = md.GetMemberReference(handle);
            if (member.Parent.Kind != HandleKind.TypeReference) continue;
            var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
            if (type.ResolutionScope.Kind == HandleKind.AssemblyReference &&
                md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope).Name) == "System.Transactions.Local" &&
                md.GetString(type.Namespace) == "System.Transactions" &&
                md.GetString(type.Name) == "TransactionScope" &&
                md.GetBlobBytes(member.Signature).AsSpan().SequenceEqual(new byte[] { 0x20, 0x00, 0x01 }))
            {
                if (md.GetString(member.Name) == ".ctor")
                {
                    caps.Add(46);
                    // Runtime failures abort a completed-source scope at the invocation boundary.
                    caps.Add(48);
                    continue;
                }
                if (md.GetString(member.Name) == "Complete")
                {
                    caps.Add(47);
                    continue;
                }
            }
            if (type.ResolutionScope.Kind == HandleKind.AssemblyReference)
            {
                var reference = md.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope);
                var assembly = md.GetString(reference.Name);
                var ns = md.GetString(type.Namespace);
                var owner = md.GetString(type.Name);
                var name = md.GetString(member.Name);
                if (!Mc04Abi.ContainsName(assembly, ns, owner, name)) continue;
                var signature = member.DecodeMethodSignature(types, null);
                var definition = Mc04Abi.Find(assembly, ns, owner, name, signature.Header.IsInstance,
                    signature.ParameterTypes, signature.ReturnType);
                if (definition is not null)
                {
                    if (definition.Capability >= 0) caps.Add(definition.Capability);
                    continue;
                }
            }
        }
        foreach (var typeHandle in md.TypeDefinitions)
        {
            var type = md.GetTypeDefinition(typeHandle);
            foreach (var attributeHandle in type.GetCustomAttributes())
            {
                var attribute = md.GetCustomAttribute(attributeHandle);
                if (Attr(attribute) != "CardAssemblyAttribute") continue;
                if (entry_points.Count >= 4) throw new Exception("Entry-point quota exceeded");
                var reader = md.GetBlobReader(attribute.Value);
                if (reader.ReadUInt16() != 1) throw new Exception("Attribute blob");
                var aid = reader.ReadSerializedString()!;
                var hooks = new Dictionary<string, int?> { { "install", null }, { "select", null }, { "deselect", null }, { "uninstall", null } };
                foreach (var methodHandle in type.GetMethods())
                {
                    var method = md.GetMethodDefinition(methodHandle);
                    var name = md.GetString(method.Name);
                    if (name is not ("Install" or "Select" or "Deselect" or "Process" or "Uninstall"))
                        continue;
                    var key = name.ToLowerInvariant();
                    if (hooks.GetValueOrDefault(key) != null) throw new Exception("Duplicate lifecycle hook");
                    var signature = method.DecodeSignature(types, null);
                    if (signature.Header.IsInstance || signature.ParameterTypes.Length != 0 ||
                        signature.ReturnType != "void" ||
                        (method.Attributes & System.Reflection.MethodAttributes.MemberAccessMask) !=
                            System.Reflection.MethodAttributes.Public)
                        throw new Exception("Lifecycle hooks must be public static parameterless void methods");
                    hooks[key] = ids[methodHandle];
                }
                if (hooks.GetValueOrDefault("process") is null) throw new Exception("Missing Process");
                entry_points.Add(new { aid, process = hooks["process"], install = hooks["install"], select = hooks["select"], deselect = hooks["deselect"], uninstall = hooks["uninstall"] });
            }
        }
    }

    void WriteManifest(string prefix)
    {
        var definition = md.GetAssemblyDefinition();
        var assembly = deviceAssemblyName;
        var version = definition.Version;
        var assemblyVersion = new[] { checked((ushort)version.Major), checked((ushort)version.Minor), checked((ushort)Math.Max(version.Build, 0)), checked((ushort)Math.Max(version.Revision, 0)) };
        File.WriteAllText(prefix + ".map.json", JsonSerializer.Serialize(ids.Select(pair => new { id = pair.Value, type = md.GetString(md.GetTypeDefinition(md.GetMethodDefinition(pair.Key).GetDeclaringType()).Name), method = md.GetString(md.GetMethodDefinition(pair.Key).Name) })));
        File.WriteAllText(prefix + ".json", JsonSerializer.Serialize(new { assembly, assembly_version = assemblyVersion, export = ExportPolicy(), entry_points, dependencies = dependencies.Select(item => item.Manifest), capabilities = caps, storage }));
    }
    public void WriteMc04(string prefix)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(prefix))!);
        CollectMc04Manifest();
        Mc04Writer.Write(input, prefix + ".mca", frameworkName, frameworkHash, deviceAssemblyName,
            dependencies.Where(item => item.HasExplicitReference).ToDictionary(item => item.ReferenceName, item => item.Name, StringComparer.Ordinal));
        WriteManifest(prefix);
    }
    public void Dispose() { pe.Dispose(); file.Dispose(); }
}
