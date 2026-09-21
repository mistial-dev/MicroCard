"""Focused validation suites used by the everyday gate."""
from validation_common import ROOT, build_managed, run

PROJECTS = ['tests/DeviceFormats', 'managed/MicroCard.Analyzers', 'managed/MicroCard.Tool', 'managed/MicroCard.Pack', 'managed/MicroCard.Bundle', 'managed/MicroCard.Iso7816', 'managed/MicroCard.Encoding', 'managed/MicroCard.Cryptography', 'managed/MicroCard.Security', 'samples/CoreLib', 'samples/CoreConsumer', 'samples/Counter', 'samples/TransactionRecords', 'samples/CryptographyConsumer', 'samples/SecurityConsumer', 'samples/Credential', 'tests/CoreReference', 'tests/Iso7816Reference', 'tests/EncodingReference', 'tests/CryptographyReference']
REFERENCES = (
    ("Iso7816Reference", "MicroCard.Iso7816.Tests"),
    ("EncodingReference", "MicroCard.Encoding.Tests"),
    ("CoreReference", "MicroCard.Core.Tests"),
    ("CryptographyReference", "MicroCard.Cryptography.Tests"),
)


def schemas():
    for name in ("mc04_schema", "mc04_opcodes", "jcvm_opcodes", "jcvm_api"):
        run("python3", f"scripts/generate_{name}.py", "--check")
    for name in ("package_envelope_test", "device_cbor_test", "prepare_first_flash_test", "doc_links", "jcvm_cap_inventory_test", "copy_audit", "profile_enforcement_audit"):
        run("python3", f"scripts/{name}.py")
    run("python3", "scripts/jcvm_api_surface.py",
        "crates/microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb",
        "crates/microcard-engine-jcvm/tests/vectors/jcalgtest-v1.8.2-jc305.lfdb",
        "--output", "format/jcvm-applet-api-surface.json", "--check")


def rust():
    run("cargo", "check", "--workspace", "--all-targets", "--locked")
    run("cargo", "test", "-p", "microcard-core", "--locked", "--no-default-features",
        "--features", "software-crypto", "--test", "shared_transport")
    run("cargo", "test", "-p", "microcard-core", "--locked", "--no-default-features",
        "--features", "software-crypto,jcvm", "--lib", "jcvm_")


def managed(jobs=1):
    build_managed(PROJECTS, jobs)
    managed_checks()


def managed_checks():
    run("dotnet", str(ROOT / "tests/DeviceFormats/bin/Release/net10.0/DeviceFormats.dll"), str(ROOT / "format/manifest-cbor-v1.json"))
    for project, assembly in REFERENCES:
        run("dotnet", str(ROOT / f"tests/{project}/bin/Release/net10.0/{assembly}.dll"))
