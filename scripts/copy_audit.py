#!/usr/bin/env python3
"""Reject unreviewed buffer-copy sites in package, linker and runtime code."""

from collections import Counter
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKENS = (".clone()", ".to_vec()", ".to_owned()", "Vec::from(", "extend_from_slice(", "copy_from_slice(")

AUDITED = {
    "crates/microcard-core/src/package.rs": [
        "raw.extend_from_slice(verified.raw);",
        "&self.raw[self.image.clone()]",
    ],
    "crates/microcard-core/src/assembly.rs": [
        "copied.extend_from_slice(incoming);",
        "stack.extend_from_slice(initial);",
    ],
    "crates/microcard-core/src/mc04_vm.rs": [],
    "crates/microcard-core/src/mc04_vm/heap.rs": [
        # Slab growth wipes the old allocation; native results are wiped after transfer.
        "next.extend_from_slice(&self.data);",
        "header[2..4].copy_from_slice(&owner.to_le_bytes());",
        "header[4..6].copy_from_slice(&length_word.to_le_bytes());",
        "self.bytes_mut(handle)?.copy_from_slice(&values);",
        "self.data[at..at + 4].copy_from_slice(&value.to_le_bytes());",
    ],
    "crates/microcard-core/src/domains.rs": [
        "merged.extend_from_slice(&self.storage_schema);",
        "copy.extend_from_slice(value);",
        "copy.extend_from_slice(value);",
        # Clones a pair of offsets, not package bytes.
        "image: raw.get(metadata.image.clone()).ok_or(Error::Storage)?,",
        # MC04 recovery still owns one shared immutable package buffer.
        "raw.extend_from_slice(bytes);",
        "host.out.extend_from_slice(&host.sw.to_be_bytes());",
        "self.out.extend_from_slice(source);",
        "version[index * 2..index * 2 + 2].copy_from_slice(&component.to_be_bytes());",
        ".copy_from_slice(&crate::globalplatform::ISD_AID);",
        "heap.bytes_mut(destination)?[destination_offset..destination_end].copy_from_slice(source);",
        ".copy_from_slice(digest.as_slice());",
    ],
    "crates/microcard-core/src/domains/lifecycle.rs": [
        # Protect descriptors for uncertain activations until recovery resolves them.
        "protected.extend_from_slice(&self.uncommitted_images);",
    ],
    "crates/microcard-core/src/staging.rs": [
        "bytes.extend_from_slice(&self.bytes);",
        "self.bytes.extend_from_slice(bytes);",
    ],
}


def production_lines(path: pathlib.Path) -> list[str]:
    source = path.read_text()
    source = source.split("\n#[cfg(test)]\nmod tests", 1)[0]
    return [line.strip() for line in source.splitlines() if any(token in line for token in TOKENS)]


def main() -> None:
    failures = []
    total = 0
    for relative, expected in AUDITED.items():
        actual = production_lines(ROOT / relative)
        total += len(actual)
        if Counter(actual) != Counter(expected):
            failures.append((relative, Counter(actual) - Counter(expected), Counter(expected) - Counter(actual)))
    tool = (ROOT / "managed/MicroCard.Tool/Mc04Writer.cs").read_text()
    forbidden = [
        "tables.ToArray()",
        "strings.ToArray()",
        "blobs.ToArray()",
        "code.ToArray()",
        "assembly.ToArray()",
        "File.WriteAllBytes(output",
    ]
    found = [value for value in forbidden if value in tool]
    if found:
        failures.append(("managed/MicroCard.Tool/Mc04Writer.cs", Counter(found), Counter()))
    if failures:
        for path, added, removed in failures:
            print(f"FAIL: copy audit changed in {path}")
            for line, count in added.items():
                print(f"  added {count}x: {line}")
            for line, count in removed.items():
                print(f"  removed {count}x: {line}")
        raise SystemExit(1)
    print(f"PASS: {total} bounded Rust copy sites audited; host MC04 emission has no full-section copies")


if __name__ == "__main__":
    main()
