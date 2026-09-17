#!/usr/bin/env python3
"""Build deterministic MC04 inputs used by the Java credential wallet."""
import argparse
import hashlib
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIGURATION = "Release"
TFM = "net10.0"
ASSEMBLIES = (
    ("samples/CoreLib", "MicroCard.Core", "mscorlib"),
    ("managed/MicroCard.Cryptography", "MicroCard.Cryptography", "cryptography"),
    ("managed/MicroCard.Security", "MicroCard.Security", "security"),
    ("samples/WalletPersonal", "WalletPersonal", "wallet-personal"),
    ("samples/WalletWork", "WalletWork", "wallet-work"),
)


def run(*arguments: object) -> None:
    subprocess.run([str(value) for value in arguments], cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    run("dotnet", "build", "managed/MicroCard.Framework", "-c", CONFIGURATION,
        "--nologo", "--verbosity", "quiet")
    run("dotnet", "build", "managed/MicroCard.Tool", "-c", CONFIGURATION,
        "--nologo", "--verbosity", "quiet")
    framework = ROOT / "managed/MicroCard.Framework/bin" / CONFIGURATION / TFM / "MicroCard.Framework.dll"
    tool = ROOT / "managed/MicroCard.Tool/bin" / CONFIGURATION / TFM / "MicroCard.Tool.dll"
    framework_hash = hashlib.sha256(framework.read_bytes()).hexdigest()

    for project, assembly_name, stem in ASSEMBLIES:
        run("dotnet", "build", project, "-c", CONFIGURATION, "--nologo", "--verbosity", "quiet")
        assembly = ROOT / project / "bin" / CONFIGURATION / TFM / f"{assembly_name}.dll"
        prefix = output / stem
        for suffix in (".mca", ".json", ".map.json"):
            candidate = pathlib.Path(str(prefix) + suffix)
            if candidate.exists():
                candidate.unlink()
        run("dotnet", tool, assembly, prefix, framework, framework_hash)

    manifest = output / "assets.sha256"
    lines = []
    for path in sorted(output.glob("*")):
        if path.is_file() and path != manifest:
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    temporary = output / ".assets.sha256.tmp"
    temporary.write_text("".join(lines), encoding="ascii")
    shutil.move(temporary, manifest)
    print(f"Built {len(ASSEMBLIES)} wallet assemblies in {output}")


if __name__ == "__main__":
    main()
