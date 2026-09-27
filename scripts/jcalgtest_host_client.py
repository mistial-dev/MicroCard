#!/usr/bin/env python3
"""Run the pinned upstream JCAlgTest client against a provisioned host JCVM."""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from jcalgtest_gp_acceptance import APPLET, IMAGE, PACKAGE
from jcalgtest_profile import pinned_result, read_result
from jcvm_transport_acceptance import load_cap, lv
from scp03_acceptance import Client, ROOT, SIM
from device_cbor import decode
from analyze_jcalgtest_performance import inspect_log


MODES = (
    "ALG_SUPPORT_BASIC", "ALG_SUPPORT_EXTENDED", "ALG_PERFORMANCE_STATIC",
    "ALG_PERFORMANCE_VARIABLE", "ALG_ECC_PERFORMANCE", "ALG_FINGERPRINT",
)
SOURCE_LOCK = ROOT / "vendor/jcalgtest/client.lock.json"
TERMINAL = ROOT / "scripts/jcalgtest_host/MicroCardTerminal.java"


def compare_profile(candidate: pathlib.Path) -> dict:
    reference = {
        (section, name): supported
        for section, probes in pinned_result()[1].items()
        for name, supported in probes.items()
    }
    observed = {
        (section, name): supported
        for section, probes in read_result(candidate.read_bytes(), optional_unavailable=True).items()
        for name, supported in probes.items()
    }
    common = reference.keys() & observed.keys()
    return {
        "reference_probes": len(reference),
        "reference_supported": sum(reference.values()),
        "observed_probes": len(observed),
        "observed_supported": sum(observed.values()),
        "missing_probes": [list(key) for key in sorted(reference.keys() - observed.keys())],
        "extra_probes": [list(key) for key in sorted(observed.keys() - reference.keys())],
        "missing_support": [list(key) for key in sorted(key for key in common if reference[key] and not observed[key])],
        "outside_profile_support": [list(key) for key in sorted(key for key in common if observed[key] and not reference[key])],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=pathlib.Path,
                        help="JCAlgTest source at the pinned client commit")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--mode", choices=MODES, default="ALG_SUPPORT_BASIC")
    parser.add_argument("--diagnostics", action="store_true",
                        help="Compile the host simulator with JCVM instruction diagnostics")
    args = parser.parse_args()
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    expected = json.loads(SOURCE_LOCK.read_text())["reference_client_commit"]
    if revision != expected:
        parser.error(f"JCAlgTest client revision {revision} differs from pin {expected}")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error(f"Output directory must be empty: {output}")
    subprocess.run(["python3", str(ROOT / "scripts/jcalgtest_client.py"),
                    "--source", str(source), "--build-only"], check=True, cwd=ROOT)
    build = ["cargo", "build", "--locked", "-p", "microcard-sim"]
    if args.diagnostics:
        build += ["--features", "microcard-engine-jcvm/diagnostics"]
    subprocess.run(build, check=True, cwd=ROOT)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="microcard-jcalgtest-host-") as temporary:
        temporary = pathlib.Path(temporary)
        keys, state, classes = temporary / "keys", temporary / "state", temporary / "classes"
        keys.write_bytes(bytes(range(32)))
        client = Client(keys, state, "serve-jcvm-managed")
        try:
            client.connect()
            discovery = decode(client.command(0xE2, b"\0"))
            load_cap(client, discovery[4], PACKAGE, IMAGE.read_bytes())
            client.command(0xE6, lv(PACKAGE, APPLET, APPLET, b"\0", b"\xc9\0", b""), p1=0x0C)
        finally:
            client.close()
        subprocess.run(["javac", "-d", str(classes), str(TERMINAL)], check=True)
        project = source / "AlgTest_JClient"
        libraries = [project / "dist/AlgTestJClient.jar",
                     source / "libs/jcommander-1.81.jar",
                     source / "libs/json-simple-1.1.1.jar",
                     *sorted((project / "libs/JNA").glob("*.jar"))]
        if any(not library.is_file() for library in libraries):
            raise RuntimeError("The pinned JCAlgTest client is missing a required JAR")
        command = ["java", f"-Dmicrocard.simulator={SIM}",
                   f"-Dmicrocard.keys={keys}", f"-Dmicrocard.state={state}",
                   "-cp", os.pathsep.join(map(str, [classes, *libraries])),
                   "MicroCardTerminal", "-op", args.mode, "-cardname", "MicroCard-host-JCVM",
                   "-outpath", str(output), "-fresh"]
        result = subprocess.run(command, cwd=source, text=True, capture_output=True)
        (output / "client.stdout.log").write_text(result.stdout)
        (output / "client.stderr.log").write_text(result.stderr)
        csvs = sorted(output.glob("*.csv"))
        rows = sum(len(path.read_text(errors="replace").splitlines()) for path in csvs)
        failures = []
        for path in csvs:
            for line in path.read_text(errors="replace").splitlines():
                if any(marker in line.upper() for marker in (
                    "UNKONWN_ERROR", "UNKNOWN_ERROR", "CARD_HAS_RETURN_VALUE_",
                    "TIMEOUT", "CRASH")):
                    failures.append(line)
        logs = list(output.glob("ALGTEST_log_*.log"))
        session_failures = (inspect_log(logs[0].read_text(errors="replace"))
                            if len(logs) == 1 else ["missing or ambiguous APDU log"])
        metadata = {
            "mode": args.mode,
            "client_commit": revision,
            "applet_sha256": hashlib.sha256(IMAGE.read_bytes()).hexdigest(),
            "simulator_sha256": hashlib.sha256(SIM.read_bytes()).hexdigest(),
            "exit_code": result.returncode,
            "csv_files": [path.name for path in csvs],
            "csv_lines": rows,
            "error_rows": len(failures),
            "session_failures": len(session_failures),
        }
        (output / "host-run.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if result.returncode or not csvs or rows == 0 or failures or session_failures:
            raise SystemExit(f"JCAlgTest run is incomplete or failed; see {output}")
        if args.mode == "ALG_SUPPORT_EXTENDED":
            comparison = compare_profile(csvs[0])
            (output / "profile-comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
            if comparison["missing_probes"] or comparison["extra_probes"]:
                raise SystemExit(f"JCAlgTest probe matrix is incomplete; see {output}")
        print(f"PASS: pinned JCAlgTest {args.mode} completed {rows} CSV lines in {output}")


if __name__ == "__main__":
    main()
