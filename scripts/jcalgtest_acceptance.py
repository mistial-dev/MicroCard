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

# INS 75 asks for one algorithm. P1 is the JCAlgTest class and the first data
# byte is the algorithm selector. These bounds are the complete contiguous
# constant ranges in JCAlgTest's Java Card 3.0.5 source. The second response
# byte is zero for supported or CryptoException.NO_SUCH_ALGORITHM (three).
FACTORIES = {
    "Cipher": (0x11, 29, {13, 14}),
    "Signature": (0x12, 49, {33}),
    "KeyAgreement": (0x13, 9, {3}),
    "MessageDigest": (0x15, 11, {4}),
    "RandomData": (0x16, 6, {1, 2}),
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

    probes = [
        (name, algorithm, class_id, algorithm in supported)
        for name, (class_id, maximum, supported) in FACTORIES.items()
        for algorithm in range(1, maximum + 1)
    ]
    commands = [SELECT, GET_VERSION, *(
        f"b075{class_id:02x}0003{algorithm:02x}0000"
        for _, algorithm, class_id, _ in probes
    )]
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

    for (name, algorithm, class_id, supported), answer in zip(probes, answers[2:]):
        response = bytes.fromhex(answer)
        label = f"{name} algorithm {algorithm}"
        assert response[-2:] == b"\x90\x00", f"{label} answered {answer}"
        assert response[:1] == bytes([class_id]), f"{label} echoed the wrong class"
        expected = 0 if supported else 3
        assert response[1] == expected, f"{label} result was {response[1]}"

    print(f"PASS: JCAlgTest reports the expected JCVM algorithm surface ({len(probes)} factories)")


if __name__ == "__main__":
    main()
