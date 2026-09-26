#!/usr/bin/env python3
"""Build and run the pinned upstream JCAlgTest 1.8.3 desktop client."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "vendor/jcalgtest/client.lock.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="upstream JCAlgTest checkout at the pinned client commit")
    parser.add_argument("--build-only", action="store_true")
    args, client_args = parser.parse_known_args()
    if client_args[:1] == ["--"]:
        client_args.pop(0)
    source = args.source.resolve()
    expected = json.loads(LOCK.read_text())["reference_client_commit"]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if actual != expected:
        parser.error(f"JCAlgTest source is {actual}; expected {expected}")

    project = source / "AlgTest_JClient"
    jar = project / "dist/AlgTestJClient.jar"
    subprocess.run(["ant", "-q", "-f", str(project / "build.xml"), "jar"],
                   cwd=source, check=True)
    libraries = [source / "libs/jcommander-1.81.jar",
                 source / "libs/json-simple-1.1.1.jar",
                 *sorted((project / "libs/JNA").glob("*.jar"))]
    if not jar.is_file() or any(not item.is_file() for item in libraries):
        raise RuntimeError("upstream client or a required dependency JAR is missing")
    command = ["java", "-cp", os.pathsep.join(map(str, [jar, *libraries])),
               "algtestjclient.AlgTestJClient"]
    help_result = subprocess.run([*command, "--help"], cwd=source,
                                 check=True, capture_output=True, text=True)
    if "JCAlgTest 1.8.3" not in help_result.stdout:
        raise RuntimeError("built desktop client did not report version 1.8.3")
    if args.build_only:
        print(f"PASS: pinned JCAlgTest 1.8.3 client builds at {jar}")
        return
    if not client_args:
        parser.error("pass upstream client arguments after --, or use --build-only")
    if "-outpath" in client_args:
        index = client_args.index("-outpath")
        if index + 1 >= len(client_args):
            parser.error("-outpath needs a directory")
        output = Path(client_args[index + 1])
        if not output.is_absolute():
            output = source / output
        output.mkdir(parents=True, exist_ok=True)
    started = time.time_ns()
    result = subprocess.run([*command, *client_args], cwd=source, check=False)
    if "-outpath" in client_args:
        index = client_args.index("-outpath")
        if index + 1 < len(client_args):
            output = Path(client_args[index + 1])
            if not output.is_absolute():
                output = source / output
            output.mkdir(parents=True, exist_ok=True)
            (output / "client-exit-code.txt").write_text(f"{result.returncode}\n")
            if result.returncode == 0 and not any(
                path.stat().st_size > 0 and path.stat().st_mtime_ns >= started
                for path in output.glob("*.csv")
            ):
                raise RuntimeError("JCAlgTest exited without a new CSV; reader selection or the scan failed")
    result.check_returncode()


if __name__ == "__main__":
    main()
