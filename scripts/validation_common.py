"""Shared validation commands, managed build graph, and timing records."""
import json
import pathlib
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
TIMINGS = []


def run(*args, **kwargs):
    started = time.monotonic()
    code = None
    try:
        result = subprocess.run(args, cwd=ROOT, check=True, **kwargs)
        code = result.returncode
        return result
    except subprocess.CalledProcessError as failure:
        code = failure.returncode
        raise
    finally:
        elapsed = round(time.monotonic() - started, 3)
        TIMINGS.append({"command": [str(arg) for arg in args], "seconds": elapsed, "exit_code": code})
        print(f"[{elapsed:.3f}s] {args[0]} {' '.join(str(arg) for arg in args[1:3])}", flush=True)


def write_timings(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"format": 1, "stages": TIMINGS}, indent=2) + "\n")


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
