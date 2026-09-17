#!/usr/bin/env python3
"""Build one original MC04 fixture and inspect it without the Rust parser."""
import json, pathlib, struct, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def fixture():
    valid = sum(1 << table for table in (0, 2, 6, 32))
    tables = bytearray(struct.pack("<BBBBQ", 2, 0, 0, 0, valid))
    tables.extend(struct.pack("<HHHH", 1, 1, 1, 1))
    tables.extend(bytes([1]))
    tables.extend(bytes([0, 0, 0, 0, 3, 0, 0, 0, 1, 1]))
    tables.extend(bytes([0, 0, 0, 0, 0, 0, 0, 0, 5, 1]))
    tables.extend(bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]))
    sections = [tables, b"\0M\0T\0Run\0A\0", bytes([0, 3, 0, 0, 1]), struct.pack("<BBHIHHB", 0, 0, 1, 1, 0, 0, 0x2a)]
    header_size = 56; file_size = header_size + sum(map(len, sections))
    result = bytearray(b"MC04" + struct.pack("<BBHBBHI", 4, 0, 0, 4, 2, header_size, file_size))
    offset = header_size
    for kind, section in enumerate(sections, 1):
        result.extend(struct.pack("<BBII", kind, 0, offset, len(section))); offset += len(section)
    for section in sections: result.extend(section)
    return bytes(result)

def main():
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "fixture.mca"; path.write_bytes(fixture())
        output = subprocess.run(["python3", str(ROOT / "scripts/mcinspect.py"), str(path)], check=True, capture_output=True, text=True)
        parsed = json.loads(output.stdout)
        assert parsed["format"] == "MC04"
        assert [table["name"] for table in parsed["tables"]] == ["Module", "TypeDef", "MethodDef", "Assembly"]
        method = parsed["tables"][2]["rows"][0]
        assert method["token"] == "0x06000001" and method["columns"]["Name"]["value"] == "Run"
        assert method["columns"]["Body"]["code_hex"] == "2a"
        assert method["columns"]["Body"]["cil"] == [{"offset": 0, "name": "ret", "operand": None}]
        malformed = bytearray(fixture()); malformed[-1] = 0x01; path.write_bytes(malformed)
        rejected = subprocess.run(["python3", str(ROOT / "scripts/mcinspect.py"), str(path)], capture_output=True, text=True)
        assert rejected.returncode != 0 and "unsupported CIL opcode" in rejected.stderr
    print("PASS: independent MC04 section, table, token, signature and CIL inspection")

if __name__ == "__main__": main()
