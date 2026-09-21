#!/usr/bin/env python3
"""Run the vendored JCAlgTest applet through the host JCVM."""

import pathlib
import subprocess
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM = ROOT / "target/debug/microcard-sim"
LOAD_FILE = (
    ROOT
    / "crates/microcard-engine-jcvm/tests/vectors/jcalgtest-v1.8.2-jc305.lfdb"
)
CAP = ROOT / "vendor/jcalgtest/jcalgtest-v1.8.2-jc305.cap"

SELECT = "00a404000a4a43416c675465737431"
GET_VERSION = "b0e100000100"

# INS 75 asks for one algorithm. P1 is the JCAlgTest class and the three data
# bytes hold the algorithm selector. The second response byte is its result:
# zero means supported, while CryptoException.NO_SUCH_ALGORITHM is three.
PROBES = {
    "SHA-256": ("b075150003040000", 0),
    "AES-128 CBC": ("b0751100030d0000", 0),
    "ECDSA SHA-256": ("b075120003210000", 0),
    "DES CBC": ("b075110003010000", 3),
}


def main() -> None:
    with zipfile.ZipFile(CAP) as archive:
        components = {
            pathlib.PurePosixPath(name).name: archive.read(name)
            for name in archive.namelist()
            if name.endswith(".cap")
        }
    order = ("Header.cap", "Directory.cap", "Applet.cap", "Import.cap",
             "ConstantPool.cap", "Class.cap", "Method.cap", "StaticField.cap",
             "RefLocation.cap", "Export.cap")
    generated = b"".join(components[name] for name in order if name in components)
    assert generated == LOAD_FILE.read_bytes(), "vendored JCAlgTest CAP and load file differ"

    commands = [SELECT, GET_VERSION, *(command for command, _ in PROBES.values())]
    result = subprocess.run(
        [str(SIM), "serve-jcvm", str(LOAD_FILE)],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    assert not result.stderr, f"JCVM diagnostics reported:\n{result.stderr}"
    answers = result.stdout.split()
    assert len(answers) == len(commands), answers
    assert answers[0] == "9000", f"SELECT answered {answers[0]}"
    assert bytes.fromhex(answers[1][:-4]).decode("ascii") == "1.8.2_jc305"
    assert answers[1][-4:] == "9000", f"GET VERSION answered {answers[1]}"

    for (name, (_, expected)), answer in zip(PROBES.items(), answers[2:]):
        response = bytes.fromhex(answer)
        assert response[-2:] == b"\x90\x00", f"{name} answered {answer}"
        assert response[1] == expected, f"{name} result was {response[1]}"

    print("PASS: JCAlgTest reports the expected JCVM algorithm surface")


if __name__ == "__main__":
    main()
