#!/usr/bin/env python3
"""Inventory exact Java Card API methods referenced by supported applet load files.

This is a static boundary, not an execution-coverage claim. Acceptance tests prove that
reached methods work; this report makes additions visible before a missing native becomes
a runtime 6F00.
"""
import argparse
import json
import pathlib
import sys

METHOD_TAGS = {3: "virtual", 4: "super", 6: "static"}


def components(block: bytes) -> dict[int, bytes]:
    found = {}
    offset = 0
    while offset < len(block):
        if offset + 3 > len(block):
            raise ValueError("truncated component header")
        tag = block[offset]
        size = int.from_bytes(block[offset + 1:offset + 3], "big")
        end = offset + 3 + size
        if end > len(block):
            raise ValueError(f"component {tag} extends past the load file")
        if tag in found:
            raise ValueError(f"duplicate component {tag}")
        found[tag] = block[offset:end]
        offset = end
    return found


def imports(component: bytes) -> list[str]:
    count = component[3]
    offset = 4
    result = []
    for _ in range(count):
        if offset + 3 > len(component):
            raise ValueError("truncated import")
        length = component[offset + 2]
        end = offset + 3 + length
        if end > len(component):
            raise ValueError("truncated import AID")
        result.append(component[offset + 3:end].hex().upper())
        offset = end
    if offset != len(component):
        raise ValueError("trailing import data")
    return result


def references(path: pathlib.Path, api: dict[str, dict]) -> list[dict[str, str]]:
    found = components(path.read_bytes())
    if 4 not in found or 5 not in found:
        raise ValueError(f"{path.name} has no Import or ConstantPool component")
    package_aids = imports(found[4])
    pool = found[5]
    count = int.from_bytes(pool[3:5], "big")
    if len(pool) != 5 + count * 4:
        raise ValueError(f"{path.name} has an invalid constant-pool length")
    result = []
    for index in range(count):
        tag, package_token, class_token, method_token = pool[5 + index * 4:9 + index * 4]
        if tag not in METHOD_TAGS or package_token & 0x80 == 0:
            continue
        import_index = package_token & 0x7f
        if import_index >= len(package_aids):
            raise ValueError(f"constant {index} names missing import {import_index}")
        package = api.get(package_aids[import_index])
        if package is None:
            raise ValueError(f"constant {index} names unknown API package {package_aids[import_index]}")
        classes = [entry for entry in package["classes"] if entry["token"] == class_token]
        if len(classes) != 1:
            raise ValueError(f"constant {index} does not resolve class token {class_token}")
        api_class = classes[0]
        methods = [entry for entry in api_class["methods"]
                   if entry["token"] == method_token
                   and entry["static_namespace"] == (tag == 6)]
        if len(methods) != 1:
            raise ValueError(f"constant {index} does not resolve method token {method_token}")
        method = methods[0]
        result.append({"kind": METHOD_TAGS[tag], "package": package["name"],
                       "class": api_class["name"], "method": method["name"],
                       "descriptor": method["descriptor"]})
    return sorted(result, key=lambda item: tuple(item.values()))


def report(api_path: pathlib.Path, load_files: list[pathlib.Path]) -> dict[str, object]:
    document = json.loads(api_path.read_text())
    api = {package["aid"]: package for package in document["packages"]}
    applets = []
    union = set()
    for path in load_files:
        methods = references(path, api)
        keys = {tuple(item.items()) for item in methods}
        if len(keys) != len(methods):
            raise ValueError(f"{path.name} repeats an external method reference")
        union.update(keys)
        applets.append({"load_file": path.name, "method_count": len(methods), "methods": methods})
    return {"source": api_path.as_posix(),
            "note": "Static imports only. Host acceptance proves methods reached at runtime.",
            "applet_count": len(applets), "unique_method_count": len(union), "applets": applets}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("load_files", nargs="+", type=pathlib.Path)
    parser.add_argument("--api", type=pathlib.Path, default=pathlib.Path("format/jcvm-api.json"))
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    rendered = json.dumps(report(arguments.api, arguments.load_files), indent=2) + "\n"
    if arguments.output is None:
        sys.stdout.write(rendered)
    elif arguments.check:
        if not arguments.output.exists() or arguments.output.read_text() != rendered:
            raise SystemExit(f"STALE: regenerate {arguments.output} with {pathlib.Path(__file__).name}")
        print(f"PASS: {arguments.output} matches the supported JCVM applet API surface")
    else:
        arguments.output.write_text(rendered)
        print(f"Wrote {arguments.output}")


if __name__ == "__main__":
    main()
