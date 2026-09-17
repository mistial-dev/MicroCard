#!/usr/bin/env python3
"""Build and run the complete wallet demonstration on this host."""
import os
import pathlib
import platform
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def environment() -> dict[str, str]:
    result = os.environ.copy()
    result.setdefault("MAVEN_USER_HOME", str(ROOT / "work/maven-home"))
    if "JAVA_HOME" not in result and platform.system() == "Darwin":
        homebrew = pathlib.Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
        if homebrew.exists():
            result["JAVA_HOME"] = str(homebrew)
            result["PATH"] = str(homebrew / "bin") + os.pathsep + result.get("PATH", "")
    return result


def run(arguments: list[object], *, env: dict[str, str], capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(value) for value in arguments], cwd=ROOT, env=env, check=True,
                          text=True, capture_output=capture)


def main() -> None:
    env = environment()
    simulator_name = "microcard-sim.exe" if os.name == "nt" else "microcard-sim"
    wrapper_name = "mvnw.cmd" if os.name == "nt" else "mvnw"
    run(["cargo", "build", "-p", "microcard-sim"], env=env)
    run([ROOT / "wallet" / wrapper_name, "-f", ROOT / "wallet/pom.xml",
         f"-Dmaven.repo.local={ROOT / 'work/maven-repository'}", "package"], env=env)
    with tempfile.TemporaryDirectory(prefix="MicroCard acceptance with spaces ") as directory_name:
        directory = pathlib.Path(directory_name)
        assets = directory / "wallet assets"
        workspace = directory / "wallet state"
        run(["python3", ROOT / "scripts/build_wallet_assets.py", "--output", assets], env=env)
        result = run([
            "java", "-cp", os.pathsep.join((str(ROOT / "wallet/target/classes"), str(ROOT / "wallet/target/lib/*"))),
            "dev.mistial.microcard.wallet.Main", "demo",
            "--sim", ROOT / "target/debug" / simulator_name, "--assets", assets,
            "--workspace", workspace,
        ], env=env, capture=True)
        print(result.stdout, end="")
        expected = "PASS: signed loading, GPPro SCP03, native P-256, PIN recovery, persistence and SSD isolation"
        if expected not in result.stdout:
            raise RuntimeError("Wallet did not report its final acceptance result")
        for name in ("personal-credential.pem", "work-credential.pem"):
            if not (workspace / "certificates" / name).is_file():
                raise RuntimeError(f"Wallet did not create {name}")
    print("PASS: repeatable wallet build and path-safe macOS acceptance")


if __name__ == "__main__":
    main()
