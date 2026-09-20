#!/usr/bin/env python3
"""Check bundle replacement and failure recovery without building or flashing."""
import pathlib
import tempfile
from unittest.mock import patch
from prepare_first_flash import publish_bundle


def main():
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
    print("PASS: complete firmware bundle replacement and failed-publication recovery")


if __name__ == "__main__":
    main()
