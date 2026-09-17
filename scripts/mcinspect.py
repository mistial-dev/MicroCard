#!/usr/bin/env python3
"""Independent MC04 table/token inspector. This does not execute assemblies."""
import json, pathlib, struct, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "format/mc04-schema.json").read_text())
TABLES = {table["id"]: table for table in SCHEMA["tables"]}
OPCODE_SCHEMA = json.loads((ROOT / "format/mc04-opcodes.json").read_text())
OPCODES = {opcode["value"]: opcode for opcode in OPCODE_SCHEMA["opcodes"]}

def inspect(data: bytes) -> dict:
    if len(data) < 56 or data[:4] != b"MC04":
        raise ValueError("not an MC04 assembly")
    major, minor, flags, section_count, token_rows, header_size, file_size = struct.unpack_from("<BBHBBHI", data, 4)
    if (major, minor, flags, section_count, token_rows, header_size, file_size) != (4, 0, 0, 4, 2, 56, len(data)):
        raise ValueError("invalid MC04 header")
    sections = {}
    cursor = header_size
    for index, expected in enumerate(SCHEMA["sections"]):
        kind, section_flags, offset, length = struct.unpack_from("<BBII", data, 16 + index * 10)
        if kind != expected["id"] or section_flags or offset != cursor or offset + length > len(data):
            raise ValueError("noncanonical section directory")
        sections[expected["name"]] = data[offset:offset + length]
        cursor += length
    if cursor != len(data):
        raise ValueError("trailing bytes")

    strings, blobs, table_data = sections["Strings"], sections["Blob"], sections["Tables"]
    if len(table_data) < 12:
        raise ValueError("short Tables section")
    schema_major, schema_minor, heap_sizes, reserved, valid = struct.unpack_from("<BBBBQ", table_data)
    if (schema_major, schema_minor, reserved) != (SCHEMA["schema_major"], SCHEMA["schema_minor"], 0):
        raise ValueError("unsupported table schema")
    string_width, blob_width = (2 if heap_sizes & 1 else 1), (2 if heap_sizes & 2 else 1)
    cursor = 12
    rows = [0] * 64
    for table_id in range(64):
        if valid >> table_id & 1:
            rows[table_id] = struct.unpack_from("<H", table_data, cursor)[0]
            cursor += 2

    def width(kind):
        if kind in ("u16",) or kind.startswith("coded:"): return 2
        if kind == "u32": return 4
        if kind == "string": return string_width
        if kind == "blob": return blob_width
        if kind.startswith("table:"): return 1 if rows[int(kind.split(":")[1])] <= 255 else 2
        raise ValueError(f"unknown column kind {kind}")
    def heap_index(raw, at, size): return int.from_bytes(raw[at:at + size], "little")
    def string_at(offset):
        if offset == 0: return ""
        end = strings.find(b"\0", offset)
        if end < 0: raise ValueError("unterminated string")
        return strings[offset:end].decode("utf-8")
    def blob_at(offset):
        if offset == 0: return b""
        first = blobs[offset]
        if first < 0x80: header, length = 1, first
        elif first < 0xc0: header, length = 2, ((first & 0x3f) << 8) | blobs[offset + 1]
        else: raise ValueError("unsupported blob length")
        return blobs[offset + header:offset + header + length]
    def decode_cil(code):
        pc, instructions, targets = 0, [], []
        while pc < len(code):
            start, first = pc, code[pc]; pc += 1
            value = first
            if first == 0xfe:
                value = 0xfe00 | code[pc]; pc += 1
            opcode = OPCODES.get(value)
            if opcode is None: raise ValueError(f"unsupported CIL opcode 0x{value:04x}")
            operand, decoded_operand = opcode["operand"], None
            if operand in ("i8", "var_u8"):
                decoded_operand = code[pc]; pc += 1
            elif operand == "i32":
                decoded_operand = struct.unpack_from("<i", code, pc)[0]; pc += 4
            elif operand == "branch_i8":
                relative = struct.unpack_from("<b", code, pc)[0]; pc += 1
                decoded_operand = pc + relative; targets.append(decoded_operand)
            elif operand == "branch_i32":
                relative = struct.unpack_from("<i", code, pc)[0]; pc += 4
                decoded_operand = pc + relative; targets.append(decoded_operand)
            elif operand == "switch_i32":
                count = struct.unpack_from("<I", code, pc)[0]; pc += 4
                if count > OPCODE_SCHEMA["switch_limit"]: raise ValueError("switch target quota")
                relatives = struct.unpack_from(f"<{count}i", code, pc); pc += count * 4
                decoded_operand = [pc + relative for relative in relatives]; targets.extend(decoded_operand)
            elif operand.endswith("_token"):
                table, row = code[pc], struct.unpack_from("<H", code, pc + 1)[0]; pc += 3
                table_name = TABLES.get(table, {}).get("name")
                if table_name not in opcode["token_tables"] or row == 0 or row > rows[table]:
                    raise ValueError("invalid compact CIL token")
                decoded_operand = f"0x{table:02X}{row:06X}"
            instructions.append({"offset": start, "name": opcode["name"], "operand": decoded_operand})
        starts = {instruction["offset"] for instruction in instructions}
        if any(target not in starts for target in targets): raise ValueError("branch target is not an instruction")
        return instructions

    decoded = []
    for table_id in range(64):
        count = rows[table_id]
        if not count: continue
        table = TABLES.get(table_id)
        if table is None: raise ValueError(f"unsupported table 0x{table_id:02x}")
        row_width = sum(width(kind) for _, kind in table["columns"])
        output_rows = []
        for row_number in range(1, count + 1):
            raw = table_data[cursor:cursor + row_width]
            if len(raw) != row_width: raise ValueError("truncated table")
            at, values = 0, {}
            for name, kind in table["columns"]:
                size = width(kind); value = heap_index(raw, at, size); at += size
                if kind == "string": values[name] = {"offset": value, "value": string_at(value)}
                elif kind == "blob": values[name] = {"offset": value, "hex": blob_at(value).hex()}
                else: values[name] = value
            if table_id == 6:
                code_offset = values["CodeOffset"]
                if code_offset + 12 > len(sections["Code"]): raise ValueError("truncated method header")
                flags, reserved, max_stack, code_length, local_signature, resources = struct.unpack_from("<BBHIHH", sections["Code"], code_offset)
                start, end = code_offset + 12, code_offset + 12 + code_length
                if reserved or resources or end > len(sections["Code"]): raise ValueError("invalid method header")
                method_code = sections["Code"][start:end]
                values["Body"] = {"flags": flags, "max_stack": max_stack, "local_signature": local_signature, "code_hex": method_code.hex(), "cil": decode_cil(method_code)}
            output_rows.append({"token": f"0x{table_id:02X}{row_number:06X}", "columns": values})
            cursor += row_width
        decoded.append({"id": table_id, "name": table["name"], "rows": output_rows})
    if cursor != len(table_data): raise ValueError("trailing table bytes")
    return {
        "format": "MC04",
        "sections": [{"name": item["name"], "bytes": len(sections[item["name"]])} for item in SCHEMA["sections"]],
        "tables": decoded,
    }

def main():
    if len(sys.argv) != 2:
        print("usage: mcinspect.py ASSEMBLY", file=sys.stderr); return 2
    try:
        print(json.dumps(inspect(pathlib.Path(sys.argv[1]).read_bytes()), indent=2))
        return 0
    except (ValueError, IndexError, struct.error, UnicodeDecodeError) as error:
        print(str(error), file=sys.stderr); return 1

if __name__ == "__main__":
    raise SystemExit(main())
