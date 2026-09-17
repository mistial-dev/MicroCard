#!/usr/bin/env python3
"""Regenerate or verify MC04 files compiled into Rust tests and fuzz targets."""
import argparse
import hashlib
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TFM = "net10.0"
FIXTURES = (
    ("samples/CoreLib", "MicroCard.Core", "fuzz/fixtures/mscorlib.mca"),
    ("samples/Counter", "Counter", "fuzz/fixtures/counter.mca"),
    ("samples/KeyOperations", "KeyOperations", "fuzz/fixtures/key_operations.mca"),
    ("samples/Kdf108", "Kdf108", "fuzz/fixtures/kdf108.mca"),
    ("samples/Kdf108Consumer", "Kdf108Consumer", "fuzz/fixtures/kdf108_consumer.mca"),
    ("managed/MicroCard.Cryptography", "MicroCard.Cryptography", "fuzz/fixtures/cryptography.mca"),
    ("samples/CryptographyConsumer", "CryptographyConsumer", "fuzz/fixtures/cryptography_consumer.mca"),
    ("managed/MicroCard.Security", "MicroCard.Security", "fuzz/fixtures/security.mca"),
    ("samples/Credential", "Credential", "fuzz/fixtures/credential.mca"),
    ("samples/TransactionRecords", "TransactionRecords", "tests/fixtures/transaction_records.mca"),
)


def run(*arguments: object) -> None:
    subprocess.run([str(value) for value in arguments], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    run("dotnet", "build", "managed/MicroCard.Framework", "-c", "Release", "--nologo")
    run("dotnet", "build", "managed/MicroCard.Tool", "-c", "Release", "--nologo")
    framework = ROOT / "managed/MicroCard.Framework/bin/Release" / TFM / "MicroCard.Framework.dll"
    tool = ROOT / "managed/MicroCard.Tool/bin/Release" / TFM / "MicroCard.Tool.dll"
    pin = hashlib.sha256(framework.read_bytes()).hexdigest()
    stale = []
    with tempfile.TemporaryDirectory(prefix="microcard-fixtures-") as directory_name:
        directory = pathlib.Path(directory_name)
        for index, (project, assembly_name, destination_name) in enumerate(FIXTURES):
            run("dotnet", "build", project, "-c", "Release", "--nologo")
            assembly = ROOT / project / "bin/Release" / TFM / f"{assembly_name}.dll"
            prefix = directory / str(index)
            run("dotnet", tool, assembly, prefix, framework, pin)
            generated = prefix.with_suffix(".mca").read_bytes()
            destination = ROOT / destination_name
            if destination.exists() and destination.read_bytes() == generated:
                continue
            if args.check:
                stale.append(destination_name)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(generated)
    if stale:
        raise SystemExit("Stale embedded fixtures:\n  " + "\n  ".join(stale))
    print("PASS: embedded MC04 corpus matches deterministic source output")


if __name__ == "__main__":
    main()
