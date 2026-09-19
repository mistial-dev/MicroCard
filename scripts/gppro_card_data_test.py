#!/usr/bin/env python3
"""Check MicroCard discovery data with an explicitly supplied GlobalPlatformPro jar."""
from device_cbor import manifest as encode_manifest
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scp03_acceptance import Client, ensure_assembly, package_envelope

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM = ROOT / "target/debug/microcard-sim"


def lv(value):
    assert len(value) <= 127
    return bytes([len(value)]) + value


def command(ins, p1, p2, data):
    assert len(data) <= 255
    return bytes([0x80, ins, p1, p2, len(data)]) + data + b"\x00"


def package_for(project, output, domain, incarnation, signing_seed):
    image_path, metadata_path = ensure_assembly(project, output)
    image = image_path.read_bytes()
    generated = json.loads(metadata_path.read_text())
    manifest = dict(
        domain=domain,
        incarnation=list(incarnation),
        assembly=generated["assembly"],
        assembly_version=generated["assembly_version"],
        version=1,
        export=generated["export"],
        entry_points=[
            dict(
                aid=entry["aid"],
                process=entry["process"],
                install=entry["install"],
                uninstall=entry["uninstall"],
                select=entry["select"],
                deselect=entry["deselect"],
            )
            for entry in generated["entry_points"]
        ],
        dependencies=generated["dependencies"],
        capabilities=generated["capabilities"],
        storage=generated["storage"],
        limits=dict(arena=16384, stack=256, frames=32, instructions=100000),
    )
    metadata = encode_manifest(manifest)
    return package_envelope(metadata, image, signing_seed)


def c4(value):
    length = len(value)
    if length <= 0x7F:
        return bytes([0xC4, length]) + value
    if length <= 0xFF:
        return bytes([0xC4, 0x81, length]) + value
    return bytes([0xC4, 0x82]) + length.to_bytes(2, "big") + value


def load_options(package, domain_aid):
    digest = hashlib.sha256(package).digest()
    load_aid = bytes.fromhex("A0000001514C") + digest[:10]
    commands = [
        command(
            0xE6,
            0x02,
            0,
            lv(load_aid) + lv(domain_aid) + lv(digest) + lv(b"") + lv(b""),
        )
    ]
    transfer = c4(package)
    chunks = list(transfer[index : index + 180] for index in range(0, len(transfer), 180))
    for block, chunk in enumerate(chunks):
        commands.append(command(0xE8, 0x80 if block + 1 == len(chunks) else 0, block, chunk))
    return load_aid, [item for apdu in commands for item in ("--secure-apdu", apdu.hex())]


def domain_counts(keys, state, index):
    client = Client(keys, state)
    client.connect()
    record = client.command(0xE2, bytes([index]))
    client.close()
    identifier_length = record[3]
    offset = 4 + identifier_length + 16 + 1 + 32
    assert len(record) == offset + 4
    return record[offset], record[offset + 1], int.from_bytes(record[offset + 2:], "little")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=pathlib.Path, required=True)
    parser.add_argument("--sha256", required=True, help="required jar digest")
    args = parser.parse_args()
    jar = args.jar.resolve()
    if hashlib.sha256(jar.read_bytes()).hexdigest() != args.sha256.lower():
        raise SystemExit("GlobalPlatformPro jar digest mismatch")
    if not SIM.exists():
        raise SystemExit("build microcard-sim before running this optional interop check")

    with tempfile.TemporaryDirectory(prefix="microcard-gppro-") as directory:
        work = pathlib.Path(directory)
        keys = work / "management.key"
        keys.write_bytes(bytes(range(32)))
        keys.chmod(0o600)
        simulator = subprocess.Popen(
            [SIM, "serve", keys, work / "state"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

        def exchange(command):
            simulator.stdin.write(command.hex() + "\n")
            simulator.stdin.flush()
            line = simulator.stdout.readline()
            if not line:
                raise RuntimeError("simulator terminated")
            return bytes.fromhex(line)

        try:
            selected = exchange(bytes.fromhex("00A4040008A000000151000000"))
            assert selected[-2:] == b"\x90\x00"
            response = exchange(bytes.fromhex("80CA006600"))
            assert response[-2:] == b"\x90\x00"
            card_data = response[:-2]
        finally:
            simulator.stdin.close()
            if simulator.wait(timeout=5) != 0:
                raise RuntimeError("simulator failed")

        source = work / "CheckMicroCard.java"
        source.write_text(
            """import apdu4j.core.HexUtils;
import pro.javacard.gp.GPData;
public final class CheckMicroCard {
  public static void main(String[] args) {
    GPData.pretty_print_card_data(HexUtils.hex2bin(args[0]));
  }
}
"""
        )
        subprocess.run(["javac", "-cp", str(jar), source.name], cwd=work, check=True)
        classpath = os.pathsep.join((str(jar), str(work)))
        parsed = subprocess.run(
            ["java", "-cp", classpath, "CheckMicroCard", card_data.hex()],
            cwd=work,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert "-> Global Platform card" in parsed
        assert "-> GP Version: 2.3.1" in parsed
        assert "-> GP SCP03 (i=20)" in parsed

        runner = work / "RunMicroCard.java"
        runner.write_text(
            """import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import pro.javacard.gptool.GPTool;
import java.io.*;
public final class RunMicroCard implements BIBO {
  private final Process process;
  private final BufferedWriter input;
  private final BufferedReader output;
  RunMicroCard(String simulator, String keys, String state) throws IOException {
    process = new ProcessBuilder(simulator, "serve", keys, state).start();
    input = process.outputWriter();
    output = process.inputReader();
  }
  public byte[] transceive(byte[] command) throws BIBOException {
    try {
      input.write(java.util.HexFormat.of().formatHex(command));
      input.newLine(); input.flush();
      String line = output.readLine();
      if (line == null) throw new IOException("simulator stopped");
      byte[] response = java.util.HexFormat.of().parseHex(line);
      int sw = (response[response.length - 2] & 255) << 8 | (response[response.length - 1] & 255);
      if ((command[1] & 255) == 0xE6 || (command[1] & 255) == 0xE8) {
        if (sw != 0x9000) throw new BIBOException(String.format(
          "management INS=%02X P1=%02X P2=%02X SW=%04X",
          command[1] & 255, command[2] & 255, command[3] & 255, sw));
      }
      return response;
    } catch (IOException error) {
      throw new BIBOException("simulator exchange failed", error);
    }
  }
  public void close() {
    try { input.close(); } catch (IOException ignored) {}
    try { process.waitFor(); } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
    }
  }
  public static void main(String[] args) throws Exception {
    try (var card = new RunMicroCard(args[0], args[1], args[2])) {
      var options = new java.util.ArrayList<String>();
      options.addAll(java.util.List.of(
        "--key-enc", args[3], "--key-mac", args[4], "--key-dek", args[3],
        "--mode", "ENC", "--mode", "RMAC"));
      options.addAll(java.util.Arrays.asList(args).subList(5, args.length));
      int result = new GPTool().run(card, options.toArray(String[]::new));
      if (result != 0) throw new RuntimeException("GPTool returned " + result);
    }
  }
}
"""
        )
        subprocess.run(["javac", "-cp", str(jar), runner.name], cwd=work, check=True)

        def run_tool(*options):
            completed = subprocess.run(
                [
                    "java",
                    "-cp",
                    classpath,
                    "RunMicroCard",
                    str(SIM),
                    str(keys),
                    str(work / "state"),
                    bytes(range(16)).hex(),
                    bytes(range(16, 32)).hex(),
                    *options,
                ],
                cwd=work,
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode:
                raise AssertionError(completed.stdout + completed.stderr)
            return completed.stdout

        listed = run_tool("--list")
        assert "ISD: A000000151000000 (OP_READY)" in listed
        assert "SecurityDomain" in listed

        inventory = Client(keys, work / "state")
        inventory.connect()
        isd_record = inventory.command(0xE2, b"\x00")
        inventory.close()
        isd_length = isd_record[3]
        assert isd_record[4 : 4 + isd_length] == b"ISD"
        isd_incarnation = isd_record[4 + isd_length : 20 + isd_length]
        mscorlib = package_for(
            "samples/CoreLib", "mscorlib", "ISD", isd_incarnation, bytes([0x42]) * 32
        )
        mscorlib_path = work / "mscorlib.mcp"
        mscorlib_path.write_bytes(mscorlib)
        verified = subprocess.run(
            [SIM, "verify", mscorlib_path], cwd=ROOT, check=False, capture_output=True, text=True
        )
        assert verified.returncode == 0, verified.stdout + verified.stderr
        mscorlib_aid, ownership_options = load_options(
            mscorlib, bytes.fromhex("A000000151000000")
        )
        owned = run_tool(*ownership_options, "--list")
        assert "ISD: A000000151000000 (SECURED)" in owned
        assert f"PKG: {mscorlib_aid.hex().upper()} (LOADED)" in owned

        created = run_tool("--domain", "F04D435344", "--list")
        assert "F04D435344" in created and "SecurityDomain" in created

        inventory = Client(keys, work / "state")
        inventory.connect()
        record = inventory.command(0xE2, b"\x01")
        inventory.close()
        identifier_length = record[3]
        assert record[4 : 4 + identifier_length] == b"F04D435344"
        incarnation = record[4 + identifier_length : 20 + identifier_length]
        package = package_for(
            "samples/Counter", "counter", "F04D435344", incarnation, bytes([0x43]) * 32
        )
        package_path = work / "counter.mcp"
        package_path.write_bytes(package)
        verified = subprocess.run(
            [SIM, "verify", package_path], cwd=ROOT, check=False, capture_output=True, text=True
        )
        assert verified.returncode == 0, verified.stdout + verified.stderr
        load_aid, transfer_options = load_options(package, bytes.fromhex("F04D435344"))
        loaded = run_tool(*transfer_options, "--list")
        assert f"PKG: {load_aid.hex().upper()} (LOADED)" in loaded, (load_aid.hex(), loaded)
        assert domain_counts(keys, work / "state", 1) == (1, 0, 0)

        instance_aid = bytes.fromhex("F04D430001")
        install_data = (
            lv(load_aid)
            + lv(instance_aid)
            + lv(instance_aid)
            + lv(b"\x00")
            + lv(bytes.fromhex("C900"))
            + lv(b"")
        )
        installed = run_tool(
            "--secure-apdu", command(0xE6, 0x0C, 0, install_data).hex(), "--list"
        )
        assert f"PKG: {load_aid.hex().upper()} (LOADED)" in installed, installed
        installed_counts = domain_counts(keys, work / "state", 1)
        assert installed_counts == (1, 1, 1), (installed_counts, installed)
        run_tool("--delete", "F04D430001", "--list")
        assert domain_counts(keys, work / "state", 1) == (1, 0, 1)

        unloaded = run_tool("--delete", load_aid.hex(), "--list")
        assert load_aid.hex().upper() not in unloaded
        assert domain_counts(keys, work / "state", 1) == (0, 0, 1)
        deleted = run_tool("--delete", "F04D435344", "--list")
        assert "F04D435344" not in deleted
    print(
        "PASS: current GlobalPlatformPro discovers, creates, loads, installs, removes and deletes MicroCard content"
    )


if __name__ == "__main__":
    main()
