"""Shared validation commands, managed build graph, and timing records."""
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import pathlib
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
TIMINGS = []
STARTED = time.monotonic()


def run(*args, stage=None, **kwargs):
    started = time.monotonic()
    code = None
    try:
        kwargs.setdefault("check", True)
        result = subprocess.run(args, cwd=ROOT, **kwargs)
        code = result.returncode
        return result
    except subprocess.CalledProcessError as failure:
        code = failure.returncode
        raise
    finally:
        elapsed = round(time.monotonic() - started, 3)
        record = {"command": [str(arg) for arg in args], "seconds": elapsed, "exit_code": code}
        if stage is not None:
            record["stage"] = stage
        TIMINGS.append(record)
        print(f"[{elapsed:.3f}s] {args[0]} {' '.join(str(arg) for arg in args[1:3])}", flush=True)


def write_timings(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "format": 1,
        "wall_seconds": round(time.monotonic() - STARTED, 3),
        "stages": TIMINGS,
    }, indent=2) + "\n")


def build_managed(projects, jobs=1):
    # One graph lets MSBuild build shared references once with consistent properties.
    solution = ET.Element("Solution")
    for project in projects:
        candidates = sorted((ROOT / project).glob("*.csproj"))
        if len(candidates) != 1:
            raise ValueError(f"Expected one project in {project}")
        ET.SubElement(solution, "Project", Path="../" + candidates[0].relative_to(ROOT).as_posix())
    path = ROOT / "work/validation-managed.slnx"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = ET.tostring(solution, encoding="unicode") + "\n"
    if not path.exists() or path.read_text() != content:
        path.write_text(content)
    run("dotnet", "build", str(path), "-c", "Release", "--nologo", "--verbosity", "quiet",
        "-p:NuGetAudit=false", f"-m:{jobs}")


def prebuilt():
    """Only checkpoint's freshly built inputs may bypass their standalone build steps."""
    return os.environ.get("MICROCARD_PREBUILT") == "1"


def require_artifacts(*paths):
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"Missing prebuilt artifact: {path}")


def run_acceptance(suites, jobs):
    """Run read-only consumers with separate logs and temporary state directories."""
    started = time.monotonic()
    directory = pathlib.Path(tempfile.mkdtemp(prefix="acceptance-", dir=ROOT / "work"))

    def execute(index, script, binary):
        name = f"{index:02d}-{script}-{'binary' if binary else 'text'}"
        workspace = directory / name
        workspace.mkdir()
        log = workspace / "output.log"
        env = {**os.environ, "MICROCARD_PREBUILT": "1", "MICROCARD_BINARY": str(int(binary)),
               "TMPDIR": str(workspace), "TMP": str(workspace), "TEMP": str(workspace)}
        try:
            with log.open("w") as output:
                run("python3", f"scripts/{script}.py", stage=name, env=env, stdout=output, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            print(log.read_text(), flush=True)
            raise
        finally:
            print(f"Acceptance log: {log.relative_to(ROOT)}", flush=True)

    failures = []
    with ThreadPoolExecutor(max_workers=jobs) as workers:
        futures = [workers.submit(execute, index, script, binary)
                   for index, (script, binary) in enumerate(suites)]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as failure:
                failures.append(failure)
    elapsed = round(time.monotonic() - started, 3)
    TIMINGS.append({"command": ["acceptance", "batch"], "seconds": elapsed,
                    "exit_code": int(bool(failures)), "workers": jobs})
    print(f"[{elapsed:.3f}s] acceptance batch ({jobs} workers)", flush=True)
    if failures:
        raise failures[0]
