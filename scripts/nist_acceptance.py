#!/usr/bin/env python3
"""Run pinned upstream NIST vectors through the persistent MicroCard host transport.

Requires the user's separately installed NIST package and compiled OpenFIPS201 tools.
Only a staged copy of the upstream harness is adapted; test inputs are not rewritten.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from device_cbor import decode
from jcvm_transport_acceptance import install_openfips
from scp03_acceptance import Client, ROOT, SIM
from wallet_acceptance import environment

REVISION = "9f3b99bd0f2600beea7e5c053613d8baef2b7716"
PACKAGE = "dev.mistial.tools.openfips201.nist"


def runtime_identity():
    return dict(engine="MicroCard JCVM host",
        microcard_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        microcard_dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
        physical_execution=False, simulator_sha256=hashlib.sha256(SIM.read_bytes()).hexdigest())


def prepare_blank_seed(directory):
    keys = directory / "keys"
    keys.write_bytes(bytes(range(32)))
    client = Client(keys, directory / "state", "serve-jcvm-managed")
    try:
        client.connect()
        install_openfips(client, decode(client.command(0xe2, b"\0")))
    finally:
        client.close()


def adapt_harness(source):
    old = 'if (!"emulator".equals(options.target) && !"pcsc".equals(options.target)) {'
    new = 'if (!"emulator".equals(options.target) && !"pcsc".equals(options.target) && !"microcard".equals(options.target)) {'
    anchor = '    if ("pcsc".equals(options.target)) {\n      CardTarget target = CardTarget.parse("pcsc:" + options.reader);'
    branch = '''    if ("microcard".equals(options.target)) {
      if (profile != null || nativeVci != null || options.provision) {
        throw new IllegalArgumentException("Use a pre-provisioned MicroCard seed; upstream provisioning is not connected");
      }
      try (MicroCardNistTransport contact = new MicroCardNistTransport()) {
        installProvider(contact, MicroCardNistTransport.unsupportedContactless());
        return runTests(configuration, selected, results, true);
      }
    }
'''
    if source.count(old) != 1 or source.count(anchor) != 1:
        raise ValueError("Upstream harness integration points changed")
    return source.replace(old, new).replace(anchor, branch + anchor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=pathlib.Path)
    parser.add_argument("--config", type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path, help="New result directory")
    parser.add_argument("--provision-config", action="store_true", help="Provision the upstream P-256 test keys, certificates, PIN/PUK and AES management key")
    parser.add_argument("--seed", type=pathlib.Path, help="Closed simulator seed directory containing keys and state; default: blank applet")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--test", help="One upstream vector identifier")
    selection.add_argument("--suite", help="Upstream suite selector, e.g. card-contact")
    selection.add_argument("--check-objects", type=pathlib.Path, help="Verify an original ICAM folder through object write/reboot/readback only; no private-key or NIST conformance claim")
    parser.add_argument("--list-tests", action="store_true")
    parser.add_argument("--check-transport", action="store_true", help="Check the bridge without NIST jars, using a blank applet")
    args = parser.parse_args()
    if not args.test and not args.suite and not args.list_tests and not args.check_transport and not args.check_objects:
        parser.error("select --test, --suite, --list-tests, --check-transport, or --check-objects")
    if args.check_transport and (args.test or args.suite or args.list_tests or args.seed or args.provision_config or args.check_objects):
        parser.error("--check-transport uses an isolated blank applet")
    if args.check_objects and (args.list_tests or args.provision_config or args.seed or args.config):
        parser.error("--check-objects uses an isolated blank applet")
    if not args.check_transport and not args.check_objects and args.config is None:
        parser.error("--config is required for NIST vectors")
    upstream, output = args.upstream.resolve(), args.out.resolve()
    config = args.config.resolve() if args.config else None
    revision = subprocess.check_output(["git", "-C", upstream, "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        parser.error(f"upstream must be at {REVISION}")
    jars = upstream / "tools/piv_test_runner/local/install/TestRunnerFiles/jars"
    harness = upstream / "src/dev/mistial/tools/openfips201/nist"
    required = [SIM, ROOT / "wallet/target/classes/dev/mistial/microcard/wallet/SimulatorTransport.class"]
    if not args.check_transport:
        required.extend(([config] if config else []) + [jars / "PIV_TestRunner_modules-5.0.1.jar", upstream / "tools/jcard-v26.08.10.jar"])
    for path in required:
        if not path.is_file():
            parser.error(f"missing prerequisite: {path}")
    source = harness / "NistHarnessMain.java"
    committed = subprocess.check_output(["git", "-C", upstream, "show",
        f"{REVISION}:{source.relative_to(upstream).as_posix()}"], text=True)
    if source.read_text() != committed:
        parser.error("upstream NistHarnessMain.java has local changes")
    adapted = adapt_harness(committed)
    # Refuse stale results, and never edit the upstream checkout or its installed jars.
    output.mkdir(parents=True, exist_ok=False)
    env = environment()
    with tempfile.TemporaryDirectory(prefix="microcard-nist-build-") as temporary:
        staging = pathlib.Path(temporary)
        seed = args.seed.resolve() if args.seed else staging / "seed"
        if args.seed:
            if not (seed / "keys").is_file() or not (seed / "state").is_dir():
                parser.error("--seed must contain keys and a closed persistent state directory")
        else:
            seed.mkdir()
            prepare_blank_seed(seed)
        if args.check_transport:
            classes = staging / "classes"
            classes.mkdir()
            cp = os.pathsep.join(map(str, [ROOT / "wallet/target/classes", ROOT / "wallet/target/lib/*"]))
            interface = staging / "NistCardTransport.java"
            interface.write_bytes(subprocess.check_output(["git", "-C", upstream, "show",
                f"{REVISION}:src/dev/mistial/tools/openfips201/nist/NistCardTransport.java"]))
            subprocess.run(["javac", "--release", "21", "-cp", cp, "-d", classes, interface,
                ROOT / "scripts/nist/MicroCardNistTransport.java", ROOT / "scripts/nist/TransportCheck.java"],
                env=env, check=True)
            result = subprocess.run(["java", f"-Dmicrocard.nist.seed={seed}", f"-Dmicrocard.nist.sim={SIM}",
                "-cp", str(classes) + os.pathsep + cp, PACKAGE + ".TransportCheck"],
                env=env, text=True, capture_output=True)
            (output / "transport.log").write_text(result.stdout + result.stderr)
            print(result.stdout, end="")
            result.check_returncode()
            return
        patched = staging / "NistHarnessMain.java"
        patched.write_text(adapted)
        classes = staging / "classes"
        classes.mkdir()
        cp = os.pathsep.join(map(str, [ROOT / "wallet/target/classes", upstream / "build/test-bin",
            upstream / "build/tool-bin", upstream / "tools/jcard-v26.08.10.jar",
            jars / "*", upstream / "build/lib/*"]))
        compile_cp = cp + os.pathsep + str(upstream / "tools/sdk/jc310/lib/api_classic-3.0.5.jar")
        sources = sorted(p for p in harness.glob("*.java") if p.name != source.name)
        subprocess.run(["javac", "--release", "21", "-encoding", "UTF-8", "-cp", compile_cp,
            "-d", classes, *sources, patched, ROOT / "scripts/nist/MicroCardNistTransport.java",
            ROOT / "scripts/nist/MicroCardNistProfile.java", ROOT / "scripts/nist/MicroCardNistObjects.java"],
            env=env, check=True)
        if args.check_objects:
            fixture = args.check_objects.resolve()
            evidence = dict(**runtime_identity(), mode="ICAM object write/reboot/readback",
                upstream_revision=revision, fixture=str(fixture),
                private_keys_exercised=False, nist_vectors_run=False,
                source_sha256=hashlib.sha256((ROOT / "scripts/nist/MicroCardNistObjects.java").read_bytes()).hexdigest(),
                fixture_sha256={str(p.relative_to(fixture)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(fixture.rglob("*")) if p.is_file()})
            started = time.perf_counter()
            with (output / "objects.log").open("w") as log:
                result = subprocess.run(["java", f"-Dmicrocard.nist.seed={seed}", f"-Dmicrocard.nist.sim={SIM}",
                    "-cp", str(classes) + os.pathsep + cp, PACKAGE + ".MicroCardNistObjects", fixture],
                    env=env, stdout=log, stderr=subprocess.STDOUT)
            evidence.update(exit_code=result.returncode, elapsed_seconds=round(time.perf_counter() - started, 3))
            (output / "object-results.json").write_text(json.dumps(evidence, indent=2) + "\n")
            print(f"ICAM object check exited {result.returncode}; results: {output}")
            raise SystemExit(result.returncode)
        compat = staging / "nist-bc-compat.jar"
        subprocess.run(["java", "-cp", str(classes) + os.pathsep + cp,
            PACKAGE + ".NistCompatibilityPatcher", jars / "PIV_TestRunner_modules-5.0.1.jar", compat],
            env=env, check=True)
        manifest = dict(**runtime_identity(), upstream_revision=revision,
            upstream_harness_sha256=hashlib.sha256(committed.encode()).hexdigest(),
            adapter_sha256=hashlib.sha256((ROOT / "scripts/nist/MicroCardNistTransport.java").read_bytes()).hexdigest(),
            profile_loader_sha256=hashlib.sha256((ROOT / "scripts/nist/MicroCardNistProfile.java").read_bytes()).hexdigest(),
            nist_modules_sha256=hashlib.sha256((jars / "PIV_TestRunner_modules-5.0.1.jar").read_bytes()).hexdigest(),
            config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
            test=args.test, suite=args.suite, list_only=args.list_tests, blank_seed=args.seed is None,
            provision_config=args.provision_config,
            synthetic_atr=True,
            unsupported=["contactless transport", "full GSA ICAM credential provisioning (RSA)", "VCI suites"],
            status="running")
        report = output / "microcard-run.json"
        report.write_text(json.dumps(manifest, indent=2) + "\n")
        if args.provision_config and not args.list_tests:
            started = time.perf_counter()
            personalized = staging / "personalized-seed"
            with (output / "provision.log").open("w") as log:
                provision = subprocess.run(["java", f"-Dmicrocard.nist.seed={seed}", f"-Dmicrocard.nist.sim={SIM}",
                    "-cp", str(classes) + os.pathsep + cp, PACKAGE + ".MicroCardNistProfile",
                    config, upstream, personalized], env=env, stdout=log, stderr=subprocess.STDOUT)
            manifest["provision_seconds"] = round(time.perf_counter() - started, 3)
            if provision.returncode:
                manifest.update(status="provision_failed", exit_code=provision.returncode)
                report.write_text(json.dumps(manifest, indent=2) + "\n")
                raise SystemExit(f"Personalization failed; see {output / 'provision.log'}")
            seed = personalized
        command = ["java", f"-Dmicrocard.nist.seed={seed}", f"-Dmicrocard.nist.sim={SIM}",
            "-cp", os.pathsep.join([str(compat), str(classes), cp]), PACKAGE + ".NistHarnessMain",
            "--target", "microcard", "--config", config, "--out", output]
        if args.test:
            command.extend(["--test", args.test])
        if args.suite:
            command.extend(["--suite", args.suite])
        if args.list_tests:
            command.append("--list-tests")
        started = time.perf_counter()
        with (output / "runner.log").open("w") as log:
            result = subprocess.run(command, cwd=upstream, env=env, stdout=log, stderr=subprocess.STDOUT)
        manifest["vector_seconds"] = round(time.perf_counter() - started, 3)
        exit_code = result.returncode
        if not args.list_tests:
            try:
                cases = list(ET.parse(output / "nist-results.xml").getroot().iter("testcase"))
                skipped = sum(case.find("skipped") is not None for case in cases)
                failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
                manifest["results"] = dict(total=len(cases), passed=len(cases) - skipped - failed,
                                           failed=failed, skipped=skipped)
                if not cases or failed:
                    exit_code = exit_code or 1
            except (OSError, ET.ParseError) as error:
                manifest["result_error"] = str(error)
                exit_code = exit_code or 1
        manifest.update(status="finished", exit_code=exit_code)
        report.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"NIST runner exited {exit_code}; results: {output}")
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
