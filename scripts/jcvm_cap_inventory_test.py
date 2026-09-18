#!/usr/bin/env python3
"""Synthetic CAP archives that exercise every rejection in jcvm_cap_inventory.

Real CAP files are third-party build outputs and are absent from this repository, so the
parser is pinned here against archives built byte by byte. Each case states what a card
would have accepted had the check been missing.
"""
import io
import pathlib
import sys
import tempfile
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from jcvm_cap_inventory import inventory  # noqa: E402

PACKAGE_AID = bytes.fromhex("A00000030800001000")
DIRECTORY_ORDER = ("Header", "Directory", "Applet", "Import", "ConstantPool", "Class",
                   "Method", "StaticField", "RefLocation", "Export", "Descriptor")
TAGS = {name: index + 1 for index, name in enumerate(DIRECTORY_ORDER)}


def component(name: str, info: bytes) -> bytes:
    return bytes([TAGS[name]]) + len(info).to_bytes(2, "big") + info


def header_info(magic: bytes = bytes.fromhex("DECAFFED")) -> bytes:
    # magic, CAP 2.1, flags, package 1.10, then the length-prefixed package AID.
    return magic + bytes([1, 2, 0x04, 10, 1, len(PACKAGE_AID)]) + PACKAGE_AID


def import_info() -> bytes:
    java_lang = bytes.fromhex("A0000000620001")
    framework = bytes.fromhex("A0000000620101")
    return (bytes([2])
            + bytes([0, 1, len(java_lang)]) + java_lang
            + bytes([6, 1, len(framework)]) + framework)


def archive(components: dict[str, bytes], *, directory_sizes: dict[str, int] | None = None,
            path: pathlib.Path) -> pathlib.Path:
    """Write a CAP whose Directory agrees with its components unless told otherwise."""
    sizes = {name: len(info) for name, info in components.items()}
    table = b"".join(
        ((directory_sizes or {}).get(name, sizes.get(name, 0))).to_bytes(2, "big")
        for name in DIRECTORY_ORDER
    )
    # The Directory declares its own size too, so it is built once the table length is known.
    static_field_and_rest = bytes(9)
    directory = component("Directory", table + static_field_and_rest)
    sizes["Directory"] = len(directory) - 3
    table = b"".join(
        ((directory_sizes or {}).get(name, sizes.get(name, 0))).to_bytes(2, "big")
        for name in DIRECTORY_ORDER
    )
    directory = component("Directory", table + static_field_and_rest)
    with zipfile.ZipFile(path, "w") as target:
        target.writestr("pkg/javacard/Directory.cap", directory)
        for name, info in components.items():
            target.writestr(f"pkg/javacard/{name}.cap", component(name, info))
    return path


def well_formed(path: pathlib.Path, **overrides) -> pathlib.Path:
    components = {
        "Header": header_info(),
        "Applet": bytes([1, 5]) + bytes(3),
        "Import": import_info(),
        "Method": bytes(40),
    }
    components.update(overrides.pop("components", {}))
    return archive(components, path=path, **overrides)


def rejects(path: pathlib.Path, needle: str) -> None:
    try:
        inventory(path)
    except ValueError as error:
        assert needle in str(error), f"expected {needle!r}, got {error}"
        return
    raise AssertionError(f"accepted a CAP that should have been refused for {needle!r}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="microcard-cap-") as directory:
        directory = pathlib.Path(directory)

        record = inventory(well_formed(directory / "good.cap"))
        assert record["cap_version"] == "2.1", record["cap_version"]
        assert record["flags"] == 0x04, record["flags"]
        assert record["package_version"] == "1.10", record["package_version"]
        assert record["package_aid"] == PACKAGE_AID.hex().upper(), record["package_aid"]
        assert [entry["version"] for entry in record["imports"]] == ["1.0", "1.6"]
        # The Load File Data Block excludes Descriptor and Debug, so it is the sum of the
        # components present in section 6.3 order and nothing else.
        assert record["load_file_bytes"] == sum(record["components"].values()), record

        # A Descriptor is carried by every real CAP and must stay out of the load file.
        with_descriptor = well_formed(directory / "descriptor.cap",
                                      components={"Descriptor": bytes(64)})
        described = inventory(with_descriptor)
        assert described["components"]["Descriptor"] == 67, described["components"]
        assert described["load_file_bytes"] == record["load_file_bytes"], described

        # Anything that is not a CAP at all. Without the magic a card would be parsing
        # whatever the archive happened to contain.
        rejects(well_formed(directory / "magic.cap",
                            components={"Header": header_info(b"\0\0\0\0")}), "magic is")

        # A truncated or padded component. Its own declared size is the bound every later
        # offset in that component is checked against.
        short = well_formed(directory / "short.cap")
        with zipfile.ZipFile(short) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        entries["pkg/javacard/Method.cap"] += b"\0"
        with zipfile.ZipFile(short, "w") as target:
            for name, value in entries.items():
                target.writestr(name, value)
        rejects(short, "declares")

        # A Directory that disagrees with what the archive holds. This is the check that
        # catches an archive assembled from parts of different builds.
        rejects(well_formed(directory / "table.cap", directory_sizes={"Method": 41}),
                "directory claims")

        # An AID running past the end of the Header.
        rejects(well_formed(directory / "aid.cap",
                            components={"Header": header_info() + b"\0\0"}), "trailing bytes")

    print("PASS: 7 Java Card CAP structure assertions")


if __name__ == "__main__":
    main()
