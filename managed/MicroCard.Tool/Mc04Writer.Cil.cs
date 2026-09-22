using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

sealed partial class Mc04Writer
{
    readonly Dictionary<short, OpCode> opcodes = typeof(OpCodes).GetFields()
        .Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null)!)
        .ToDictionary(opcode => opcode.Value);

    List<Instruction> Decode(byte[] input)
    {
        var result = new List<Instruction>();
        int pc = 0;
        while (pc < input.Length)
        {
            int start = pc;
            byte first = input[pc++]; short value = first;
            if (first == 0xfe) value = unchecked((short)(0xfe00 | input[pc++]));
            if (!opcodes.TryGetValue(value, out var opcode)) throw new Exception("Unknown CIL opcode");
            EntityHandle token = default;
            int variable = -1;
            var targets = new List<int>();
            switch (opcode.OperandType)
            {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI: pc += 1; break;
                case OperandType.ShortInlineVar: variable = input[pc++]; break;
                case OperandType.InlineVar: variable = BitConverter.ToUInt16(input, pc); pc += 2; break;
                case OperandType.InlineI: case OperandType.ShortInlineR: pc += 4; break;
                case OperandType.InlineI8: case OperandType.InlineR: pc += 8; break;
                case OperandType.ShortInlineBrTarget:
                    targets.Add(pc + 1 + (sbyte)input[pc]); pc += 1; break;
                case OperandType.InlineBrTarget:
                    targets.Add(pc + 4 + BitConverter.ToInt32(input, pc)); pc += 4; break;
                case OperandType.InlineSwitch:
                {
                    int count = BitConverter.ToInt32(input, pc); pc += 4;
                    int targetBase = checked(pc + count * 4);
                    for (int index = 0; index < count; index++)
                        targets.Add(checked(targetBase + BitConverter.ToInt32(input, pc + index * 4)));
                    pc = targetBase;
                    break;
                }
                case OperandType.InlineMethod: case OperandType.InlineField:
                case OperandType.InlineType: case OperandType.InlineTok:
                case OperandType.InlineString: case OperandType.InlineSig:
                    token = MetadataTokens.EntityHandle(BitConverter.ToInt32(input, pc)); pc += 4; break;
                default: throw new Exception($"Unsupported MC04 CIL operand {opcode.OperandType}");
            }
            if (pc > input.Length) throw new Exception("Truncated CIL operand");
            result.Add(new Instruction(start, pc - start, value, token, variable, targets.ToArray()));
        }
        return result;
    }

    readonly record struct Instruction(
        int Offset, int Size, short Opcode, EntityHandle Token, int Variable, int[] BranchTargets)
    {
        public int End => checked(Offset + Size);
        public int? BranchTarget => BranchTargets.Length == 1 ? BranchTargets[0] : null;
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

