#!/usr/bin/env python3
"""Keep Rider diagnostics, negative builds, preprocessing, and device enforcement aligned."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = {f"MCA{index:04d}" for index in range(1, 26)}


def identifiers(relative: str) -> set[str]:
    return set(re.findall(r"MCA\d{4}", (ROOT / relative).read_text()))


def require(relative: str, needles: tuple[str, ...]) -> None:
    source = (ROOT / relative).read_text()
    missing = [needle for needle in needles if needle not in source]
    if missing:
        raise SystemExit(f"{relative} is missing profile enforcement: {missing}")


def main() -> None:
    analyzer = identifiers("managed/MicroCard.Analyzers/MicroCardProfileAnalyzer.cs")
    acceptance = identifiers("scripts/analyzer_cases.py")
    matrix = identifiers("docs/PROFILE_ENFORCEMENT.md")
    for name, actual in (("analyzer", analyzer), ("acceptance", acceptance), ("matrix", matrix)):
        if actual != EXPECTED:
            raise SystemExit(
                f"{name} diagnostic coverage differs: missing={sorted(EXPECTED - actual)}, "
                f"extra={sorted(actual - EXPECTED)}"
            )

    require("managed/MicroCard.Tool/Program.cs", (
        "Unsupported type flags",
        "Only Int32 fields and constants supported",
        "Unsupported method flags",
        "Method parameter quota exceeded",
        "Persistent storage declaration quota exceeded",
        '("DomainStorage", "AbortTransaction") => 48,',
    ))
    require("managed/MicroCard.Tool/Mc04Writer.cs", (
        "MC04 metadata row quota exceeded",
        "MC04 custom attribute quota exceeded",
        "MC04 exception handlers unsupported",
        "MC04 local-variable quota exceeded",
        "Switch quota",
    ))
    require("crates/microcard-core/src/package/manifest_cbor.rs", (
        "let entry_points = list(&mut d, 4,",
        "let dependencies = list(&mut d, 16,",
        "let storage = list(&mut d, MAX_STORAGE_DECLARATIONS,",
    ))
    require("crates/microcard-core/src/package.rs", (
        "assembly.validate_lifecycle(id)?",
        "assembly.validate_imports(&manifest.capabilities)?",
    ))
    require("crates/microcard-core/src/mc04_vm.rs", (
        "const MAX_TRANSIENT_BYTES: usize = 16 * 1024;",
        "const MAX_TRANSIENT_OBJECTS: usize = 256;",
    ))
    require("crates/microcard-core/src/mc04_schema.rs", (
        "MAX_TYPEDEF_ROWS: u16 = 253",
        "MAX_FIELD_ROWS: u16 = 1022",
        "MAX_METHODDEF_ROWS: u16 = 256",
        "MAX_CUSTOMATTRIBUTE_ROWS: u16 = 256",
    ))
    require("crates/microcard-core/src/domains/linking.rs", ("validate_linked_program(&units)?",))
    require("crates/microcard-core/src/domains.rs", (
        "merged_storage_schema",
        "authorize_storage",
        "domain_schema",
    ))
    print("PASS: MCA0001-MCA0025 coverage pointers and profile enforcement sites are present")


if __name__ == "__main__":
    main()
