#!/usr/bin/env python3
"""Acceptance checks for the real preprocessed MC04 Counter assembly."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mcinspect

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    path = ROOT / "work/counter.mca"
    parsed = mcinspect.inspect(path.read_bytes())
    tables = {table["name"]: table["rows"] for table in parsed["tables"]}
    assert tables["Assembly"][0]["columns"]["Name"]["value"] == "Counter"
    assert len(tables["MethodDef"]) == 31 and len(tables["CustomAttribute"]) == 10
    type_names = {row["columns"]["TypeName"]["value"] for row in tables["TypeRef"]}
    assert {
        "SecurityDomain",
        "DomainStorage",
        "CommandApdu",
        "ResponseApdu",
        "Object",
        "Byte",
        "Int32",
    } <= type_names
    assert not any("Compilation" in name or "Debug" in name or "AssemblyCompany" in name for name in type_names)
    install = next(row for row in tables["MethodDef"] if row["columns"]["Name"]["value"] == "Install")
    code = bytes.fromhex(install["columns"]["Body"]["code_hex"])
    assert code[:5] == bytes([0x28, 0x0A, 5, 0, 0x6F]), "call must use CIL opcode plus compact MemberRef token"
    current = next(row for row in tables["MemberRef"] if row["columns"]["Name"]["value"] == "get_Current")
    signature = bytes.fromhex(current["columns"]["Signature"]["hex"])
    security_domain_row = next(index for index, row in enumerate(tables["TypeRef"], 1) if row["columns"]["TypeName"]["value"] == "SecurityDomain")
    assert signature[-1] == security_domain_row << 2 | 1, "signature TypeRef token was not remapped"
    for method_name in ("EmptyBytes", "EmptyIntegers"):
        method = next(row for row in tables["MethodDef"] if row["columns"]["Name"]["value"] == method_name)
        code = bytes.fromhex(method["columns"]["Body"]["code_hex"])
        assert code[:2] == bytes([0x16, 0x8D]), "Array.Empty<T>() must normalize to ldc.i4.0/newarr"
    source_size = (ROOT / "samples/Counter/bin/Release/net10.0/Counter.dll").stat().st_size
    assert path.stat().st_size < source_size and path.stat().st_size <= 3072
    print(f"PASS: deterministic MC04 emission, dead metadata removal, token remapping and {path.stat().st_size}-byte budget")

if __name__ == "__main__": main()
