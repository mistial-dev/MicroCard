#!/usr/bin/env python3
"""Read the pinned P71D321 JCAlgTest result without changing upstream data."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "vendor/jcalgtest/p71d321-reference.csv.gz"
LOCK = ROOT / "vendor/jcalgtest/client.lock.json"


def read_result(source: bytes) -> dict[str, dict[str, bool]]:
    sections: dict[str, dict[str, bool]] = {}
    section: str | None = None
    for line in source.decode("utf-8-sig").splitlines():
        line = line.strip()
        if line.startswith("javacard.") or line.startswith("javacardx."):
            if ";" not in line:
                section = line
                if section in sections:
                    raise ValueError(f"duplicate section: {section}")
                sections[section] = {}
                continue
        if section is None or ";" not in line:
            continue
        name, status, *_ = line.split(";")
        status = status.strip()
        if status not in {"yes", "no"}:
            continue
        name = name.strip()
        if not name or name in sections[section]:
            raise ValueError(f"empty or duplicate probe: {section}/{name}")
        sections[section][name] = status == "yes"
    if not sections or not any(sections.values()):
        raise ValueError("no algorithm probes found")
    return sections


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write a JSON matrix; stdout by default")
    args = parser.parse_args()
    lock = json.loads(LOCK.read_text())
    raw = gzip.decompress(REFERENCE.read_bytes())
    digest = hashlib.sha256(raw).hexdigest()
    if digest != lock["reference_result_sha256"]:
        raise ValueError("pinned reference result changed")
    sections = read_result(raw)
    if len(sections) != 22 or sum(map(len, sections.values())) != 8607 or sum(
        sum(rows.values()) for rows in sections.values()
    ) != 288:
        raise ValueError("reference result has an incomplete probe matrix")
    result = {
        "source": "JCAlgTest 1.8.3, P71D321, 2026-06-18",
        "source_sha256": digest,
        "sections": sections,
    }
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
