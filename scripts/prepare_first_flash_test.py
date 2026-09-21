#!/usr/bin/env python3
"""Check bundle replacement and failure recovery without building or flashing."""
import pathlib
import struct
import tempfile
from unittest.mock import patch
from prepare_first_flash import NRF52840_UF2_FAMILY, publish_bundle, write_uf2
from verify_uf2_readback import addressed


def main():
    with tempfile.TemporaryDirectory() as root:
        destination = pathlib.Path(root) / "firmware.uf2"
        raw = bytes(index & 0xff for index in range(300))
        write_uf2(raw, 0x1000, destination)
        image = destination.read_bytes()
        assert len(image) == 1024
        for index, target in enumerate((0x1000, 0x1100)):
            block = image[index * 512:(index + 1) * 512]
            header = struct.unpack_from("<8I", block)
            assert header == (0x0A324655, 0x9E5D5157, 0x2000, target, 256,
                              index, 2, NRF52840_UF2_FAMILY)
            assert struct.unpack_from("<I", block, 508)[0] == 0x0AB16F30
        assert image[32:288] == raw[:256]
        assert image[544:588] == raw[256:]
        assert image[588:800] == bytes(212)
        readback = addressed(destination)
        assert bytes(readback[address] for address in sorted(readback)) == raw + bytes(212)

    for fail in (0, 1, 2):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            destination, staged = root / "published", root / "staged"
            destination.mkdir()
            staged.mkdir()
            (destination / "manifest.json").write_text("old manifest")
            (destination / "stale.bin").write_bytes(b"old image")
            (staged / "manifest.json").write_text("new manifest")
            (staged / "current.bin").write_bytes(b"new image")
            rename = pathlib.Path.rename

            def move(source, target):
                if fail and (source == staged or fail == 2 and source.parent.name.startswith(".previous-")):
                    raise OSError("injected publication failure")
                return rename(source, target)

            with patch.object(pathlib.Path, "rename", move):
                try:
                    publish_bundle(staged, destination)
                except OSError:
                    assert fail
                else:
                    assert not fail
            expected = {"manifest.json": b"old manifest", "stale.bin": b"old image"} if fail else {
                "manifest.json": b"new manifest", "current.bin": b"new image"}
            backups = list(root.glob(".previous-*"))
            if fail == 2:
                assert not destination.exists() and len(backups) == 1
                recovered = backups[0] / "bundle"
            else:
                assert not backups
                recovered = destination
            assert {p.name: p.read_bytes() for p in recovered.iterdir()} == expected
            assert staged.exists() == bool(fail)
    print("PASS: nRF52840 UF2 encoding, complete bundle replacement and failed-publication recovery")


if __name__ == "__main__":
    main()
