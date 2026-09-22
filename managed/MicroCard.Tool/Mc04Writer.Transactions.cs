using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

sealed partial class Mc04Writer
{
    byte[] RewriteTransactionScope(MethodBodyBlock body)
    {
        byte[] code = body.GetILBytes()!;
        var instructions = Decode(code);
        if (body.ExceptionRegions.Length == 0)
        {
            if (instructions.Any(instruction =>
                    !instruction.Token.IsNil && TransactionControl(instruction.Token) != 0))
                throw new Exception("TransactionScope requires a canonical using declaration");
            return code;
        }
        if (body.ExceptionRegions.Length != 1 ||
            body.ExceptionRegions[0].Kind != ExceptionRegionKind.Finally)
            throw new Exception("MC04 exception handlers unsupported");

        var region = body.ExceptionRegions[0];
        int tryStart = region.TryOffset;
        int tryEnd = checked(tryStart + region.TryLength);
        int handlerStart = region.HandlerOffset;
        int handlerEnd = checked(handlerStart + region.HandlerLength);
        if (tryEnd != handlerStart || handlerEnd > code.Length)
            throw new Exception("TransactionScope requires a canonical using declaration");

        var beforeTry = instructions.Where(instruction => instruction.Offset < tryStart).ToArray();
        if (beforeTry.Length < 2 || beforeTry[^2].Opcode != OpCodes.Newobj.Value ||
            TransactionControl(beforeTry[^2].Token) != 1)
            throw new Exception("MC04 exception handlers unsupported");
        if (beforeTry[^1].End != tryStart ||
            LocalIndex(beforeTry[^1], store: true) is not int scopeLocal)
            throw new Exception("TransactionScope requires a canonical using declaration");
        var constructor = (MemberReferenceHandle)beforeTry[^2].Token;

        var tryInstructions = instructions.Where(instruction =>
            instruction.Offset >= tryStart && instruction.Offset < tryEnd).ToArray();
        if (tryInstructions.Length == 0 || tryInstructions[^1].End != tryEnd ||
            tryInstructions[^1].Opcode is not (0xdd or 0xde) ||
            tryInstructions[^1].BranchTarget != handlerEnd)
            throw new Exception("TransactionScope requires one normal scope exit");
        var payload = tryInstructions[..^1];
        MemberReferenceHandle completion = default;
        bool completed = payload.Length >= 2 &&
            LocalIndex(payload[^2], store: false) == scopeLocal &&
            payload[^1].Opcode == OpCodes.Callvirt.Value &&
            TransactionControl(payload[^1].Token) == 2;
        if (completed)
        {
            completion = (MemberReferenceHandle)payload[^1].Token;
            payload = payload[..^2];
        }

        var handler = instructions.Where(instruction =>
            instruction.Offset >= handlerStart && instruction.Offset < handlerEnd).ToArray();
        if (handler.Length != 5 || handler[^1].End != handlerEnd ||
            LocalIndex(handler[0], store: false) != scopeLocal ||
            handler[1].Opcode is not (0x2c or 0x39) ||
            handler[1].BranchTarget != handler[4].Offset ||
            LocalIndex(handler[2], store: false) != scopeLocal ||
            handler[3].Opcode != OpCodes.Callvirt.Value ||
            TransactionControl(handler[3].Token) != 3 ||
            handler[4].Opcode != OpCodes.Endfinally.Value)
            throw new Exception("TransactionScope requires the compiler-generated disposal finally");
        var disposal = (MemberReferenceHandle)handler[3].Token;

        foreach (var instruction in payload)
        {
            if ((!instruction.Token.IsNil && TransactionControl(instruction.Token) != 0) ||
                LocalIndex(instruction, store: false) == scopeLocal ||
                LocalIndex(instruction, store: true) == scopeLocal ||
                instruction.Opcode is 0xdd or 0xde or 0xdc or 0x2a)
                throw new Exception("TransactionScope cannot escape or use noncanonical control flow");
            ValidateBranches(instruction, tryStart,
                payload.Length == 0 ? tryStart : payload[^1].End);
        }
        int constructorStart = beforeTry[^2].Offset;
        foreach (var instruction in instructions)
        {
            if (instruction.Offset < constructorStart)
                ValidateBranches(instruction, 0, constructorStart);
            else if (instruction.Offset >= handlerEnd)
                ValidateBranches(instruction, handlerEnd, code.Length);
        }

        ProjectTransaction(constructor, "Begin");
        if (completed) ProjectTransaction(completion, "Commit");
        else ProjectTransaction(disposal, "Abort");

        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, true);
        writer.Write(code, 0, constructorStart);
        WriteProjectedCall(writer, constructor);
        int payloadEnd = payload.Length == 0 ? tryStart : payload[^1].End;
        writer.Write(code, tryStart, payloadEnd - tryStart);
        WriteProjectedCall(writer, completed ? completion : disposal);
        writer.Write(code, handlerEnd, code.Length - handlerEnd);
        return output.ToArray();
    }

    void ProjectTransaction(MemberReferenceHandle member, string name)
    {
        var parent = md.GetMemberReference(member).Parent;
        if (parent.Kind != HandleKind.TypeReference)
            throw new Exception("TransactionScope projection requires a type reference");
        projectedTransactionTypes[(TypeReferenceHandle)parent] = "TransactionScopeRuntime";
        var projection = (name, true);
        if (projectedTransactionMembers.TryGetValue(member, out var existing) && existing != projection)
            throw new Exception("Conflicting TransactionScope projection");
        projectedTransactionMembers[member] = projection;
    }

    bool ProjectTransactionQuery(MemberReferenceHandle memberHandle)
    {
        var member = md.GetMemberReference(memberHandle);
        if (member.Parent.Kind != HandleKind.TypeReference) return false;
        var parent = (TypeReferenceHandle)member.Parent;
        if (!IsSystemTransactions(parent)) return false;
        string owner = md.GetString(md.GetTypeReference(parent).Name);
        string memberName = md.GetString(member.Name);
        (string RuntimeOwner, string RuntimeMember, byte Calling, byte ResultKind, string ResultType)? shape =
            (owner, memberName) switch
            {
                ("Transaction", "get_Current") =>
                    ("TransactionRuntime", "Current", 0x00, 0x12, "Transaction"),
                ("Transaction", "get_TransactionInformation") =>
                    ("TransactionRuntime", "Information", 0x20, 0x12, "TransactionInformation"),
                ("TransactionInformation", "get_Status") =>
                    ("TransactionInformationRuntime", "Status", 0x20, 0x11, "TransactionStatus"),
                _ => null,
            };
        if (shape is null) return false;
        var expected = shape.Value;
        if (!TransactionGetterSignature(member.Signature, expected.Calling,
                expected.ResultKind, expected.ResultType))
            throw new Exception("Unexpected System.Transactions query signature");
        projectedTransactionTypes[parent] = expected.RuntimeOwner;
        ProjectTransactionType(expected.ResultType,
            expected.ResultType == "Transaction" ? "TransactionRuntime" :
            expected.ResultType == "TransactionInformation" ? "TransactionInformationRuntime" :
            "TransactionStatusRuntime");
        projectedTransactionMembers[memberHandle] = (expected.RuntimeMember, false);
        return true;
    }

    void ProjectTransactionType(string source, string runtime)
    {
        foreach (var handle in md.TypeReferences)
        {
            var type = md.GetTypeReference(handle);
            if (IsSystemTransactions(handle) && md.GetString(type.Name) == source)
                projectedTransactionTypes[handle] = runtime;
        }
    }

    bool TransactionGetterSignature(BlobHandle signatureHandle, byte calling,
        byte resultKind, string resultType)
    {
        byte[] signature = md.GetBlobBytes(signatureHandle);
        if (signature.Length < 4 || signature[0] != calling || signature[1] != 0 ||
            signature[2] != resultKind) return false;
        int cursor = 3;
        uint coded;
        byte first = signature[cursor++];
        if (first < 0x80) coded = first;
        else if (first < 0xc0 && cursor < signature.Length)
            coded = checked((uint)((first & 0x3f) << 8 | signature[cursor++]));
        else return false;
        if (cursor != signature.Length || (coded & 3) != 1 || (coded >> 2) == 0)
            return false;
        var result = MetadataTokens.TypeReferenceHandle(checked((int)(coded >> 2)));
        var type = md.GetTypeReference(result);
        return IsSystemTransactions(result) && md.GetString(type.Name) == resultType;
    }

    static void WriteProjectedCall(BinaryWriter writer, MemberReferenceHandle member)
    {
        writer.Write((byte)OpCodes.Call.Value);
        writer.Write(MetadataTokens.GetToken(member));
    }

    void ValidateBranches(Instruction instruction, int start, int end)
    {
        foreach (int target in instruction.BranchTargets)
            if (target < start || target >= end)
                throw new Exception("TransactionScope cannot cross a control-flow boundary");
    }

    int TransactionControl(EntityHandle handle)
    {
        if (handle.Kind != HandleKind.MemberReference) return 0;
        var member = md.GetMemberReference((MemberReferenceHandle)handle);
        if (member.Parent.Kind != HandleKind.TypeReference) return 0;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (type.ResolutionScope.Kind != HandleKind.AssemblyReference) return 0;
        string assembly = md.GetString(md.GetAssemblyReference(
            (AssemblyReferenceHandle)type.ResolutionScope).Name);
        string ns = md.GetString(type.Namespace);
        string typeName = md.GetString(type.Name);
        string memberName = md.GetString(member.Name);
        byte[] signature = md.GetBlobBytes(member.Signature);
        bool parameterlessVoid = signature.AsSpan().SequenceEqual(new byte[] { 0x20, 0x00, 0x01 });
        if (!parameterlessVoid) return 0;
        if (assembly == "System.Transactions.Local" && ns == "System.Transactions" &&
            typeName == "TransactionScope")
            return memberName == ".ctor" ? 1 : memberName == "Complete" ? 2 : 0;
        return assembly == "System.Runtime" && ns == "System" && typeName == "IDisposable" &&
               memberName == "Dispose" ? 3 : 0;
    }

    static int? LocalIndex(Instruction instruction, bool store) => instruction.Opcode switch
    {
        0x06 when !store => 0, 0x07 when !store => 1, 0x08 when !store => 2, 0x09 when !store => 3,
        0x0a when store => 0, 0x0b when store => 1, 0x0c when store => 2, 0x0d when store => 3,
        0x11 when !store => instruction.Variable,
        0x13 when store => instruction.Variable,
        unchecked((short)0xfe0c) when !store => instruction.Variable,
        unchecked((short)0xfe0e) when store => instruction.Variable,
        _ => null,
    };

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
        {
            if (!ReachesExplicitControl(handle)) continue;
            transactionalMethods.Add(handle);
            if (ReachesIrreversibleOutput(handle))
                throw new Exception("Transactional method reaches irreversible AssemblyContext.Current.Runtime.WriteHardware");
        }
    }

    bool IsExplicitTransactionControl(MemberReferenceHandle handle)
    {
        if (projectedTransactionMembers.ContainsKey(handle)) return true;
        return TransactionControl(handle) != 0;
    }

    bool IsIrreversibleOutput(MemberReferenceHandle handle)
    {
        var member = md.GetMemberReference(handle);
        if (md.GetString(member.Name) != "WriteHardware" || member.Parent.Kind != HandleKind.TypeReference)
            return false;
        var type = md.GetTypeReference((TypeReferenceHandle)member.Parent);
        if (md.GetString(type.Name) != "RuntimeService" ||
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
}
