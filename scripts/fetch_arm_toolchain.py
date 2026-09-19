#!/usr/bin/env python3
"""Install a checksum-pinned Arm compiler under work/ without changing system tools."""
import argparse
import hashlib
import os
import pathlib
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/"
# Published by Arm in the adjacent .sha256asc files.
ARCHIVES = {
    ("Linux", "x86_64"): ("x86_64", "tar.xz", "95c011cee430e64dd6087c75c800f04b9c49832cc1000127a92a97f9c8d83af4"),
    ("Darwin", "arm64"): ("darwin-arm64", "tar.xz", "fb6921db95d345dc7e5e487dd43b745e3a5b4d5c0c7ca4f707347148760317b4"),
    ("Darwin", "x86_64"): ("darwin-x86_64", "tar.xz", "1ab00742d1ed0926e6f227df39d767f8efab46f5250505c29cb81f548222d794"),
    ("Windows", "amd64"): ("mingw-w64-i686", "zip", "e46fda043c0ce83582bc8db4b3ef85f77f4beb7333344c2f4193c17e1167a095"),
}


def install(directory):
    host = (platform.system(), platform.machine().lower())
    if host not in ARCHIVES:
        raise SystemExit(f"No pinned Arm toolchain for {host}")
    target, extension, digest = ARCHIVES[host]
    name = f"arm-gnu-toolchain-13.3.rel1-{target}-arm-none-eabi"
    destination = directory / name
    executable = "arm-none-eabi-gcc" + (".exe" if host[0] == "Windows" else "")
    directory.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with tempfile.TemporaryDirectory(prefix=".arm-fetch-", dir=directory) as temporary:
            temporary = pathlib.Path(temporary)
            archive = temporary / (name + "." + extension)
            print(f"Downloading {archive.name}", flush=True)
            with urllib.request.urlopen(BASE + archive.name, timeout=120) as response, archive.open("wb") as output:
                shutil.copyfileobj(response, output)
            with archive.open("rb") as source:
                actual = hashlib.file_digest(source, "sha256").hexdigest()
            if actual != digest:
                raise SystemExit(f"Arm archive checksum mismatch: {actual}")
            unpacked = temporary / "unpacked"
            unpacked.mkdir()
            if extension == "zip":
                with zipfile.ZipFile(archive) as source:
                    for member in source.infolist():
                        resolved = (unpacked / member.filename).resolve()
                        if not resolved.is_relative_to(unpacked.resolve()):
                            raise SystemExit("Unsafe toolchain archive path")
                    source.extractall(unpacked)
            else:
                with tarfile.open(archive) as source:
                    source.extractall(unpacked, filter="data")
            compiler = unpacked / name / "bin" / executable
            # Some Arm zip distributions omit the enclosing directory.
            extracted = unpacked / name if compiler.exists() else unpacked
            verify(extracted / "bin" / executable)
            extracted.rename(destination)
    verify(destination / "bin" / executable)
    return destination / "bin"


def verify(compiler):
    version = subprocess.check_output([str(compiler), "-dumpfullversion"], text=True).strip()
    if version != "13.3.1":
        raise SystemExit(f"Unexpected Arm compiler version: {version}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=pathlib.Path, default=ROOT / "work" / "toolchains")
    args = parser.parse_args()
    binary_directory = install(args.directory.resolve())
    if os.environ.get("GITHUB_PATH"):
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
            output.write(str(binary_directory) + "\n")
    print(f"Arm GNU 13.3.Rel1 tools: {binary_directory}")
    print("Add this directory to PATH before building firmware.")


if __name__ == "__main__":
    main()
