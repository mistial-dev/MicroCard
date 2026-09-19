#!/usr/bin/env python3
"""Create a self-contained host bundle and nRF52840 development artifacts."""
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "0.1-wip"


def run(arguments: list[object], *, env: dict[str, str] | None = None,
        cwd: pathlib.Path = ROOT) -> None:
    subprocess.run([str(value) for value in arguments], cwd=cwd, env=env, check=True)


def copy_tree(source: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def main() -> None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in ("arm64", "aarch64"):
        platform_name = "macos-arm64"
    elif system == "linux" and machine in ("x86_64", "amd64"):
        platform_name = "linux-x64"
    elif system == "windows" and machine in ("x86_64", "amd64"):
        platform_name = "windows-x64"
    else:
        raise RuntimeError(f"Unsupported release host: {system}-{machine}")

    env = os.environ.copy()
    env.setdefault("MAVEN_USER_HOME", str(ROOT / "work/maven-home"))
    if system == "darwin" and "JAVA_HOME" not in env:
        candidate = pathlib.Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
        if candidate.exists():
            env["JAVA_HOME"] = str(candidate)
            env["PATH"] = str(candidate / "bin") + os.pathsep + env.get("PATH", "")

    artifact_root = ROOT / "artifacts/release"
    stage = artifact_root / f"MicroCard-{VERSION}-{platform_name}"
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "bin").mkdir(parents=True)
    (stage / "wallet/lib").mkdir(parents=True)

    run(["cargo", "build", "--release", "-p", "microcard-sim", "--locked"], env=env)
    simulator_name = "microcard-sim.exe" if system == "windows" else "microcard-sim"
    shutil.copy2(ROOT / "target/release" / simulator_name, stage / "bin" / simulator_name)

    wrapper_name = "mvnw.cmd" if system == "windows" else "mvnw"
    run([ROOT / "wallet" / wrapper_name, "-f", ROOT / "wallet/pom.xml",
         f"-Dmaven.repo.local={ROOT / 'work/maven-repository'}", "package"],
        env=env, cwd=ROOT / "wallet")
    shutil.copy2(ROOT / "wallet/target/microcard-wallet-0.1.0-wip.jar", stage / "wallet/microcard-wallet.jar")
    for dependency in (ROOT / "wallet/target/lib").glob("*.jar"):
        shutil.copy2(dependency, stage / "wallet/lib" / dependency.name)
    run(["python3", ROOT / "scripts/build_wallet_assets.py", "--output", stage / "assemblies"], env=env)

    java_home = pathlib.Path(env.get("JAVA_HOME", pathlib.Path(sys.executable).parents[1]))
    jlink = java_home / "bin" / ("jlink.exe" if system == "windows" else "jlink")
    if not jlink.exists():
        discovered = shutil.which("jlink")
        if discovered is None:
            raise RuntimeError("Java 21 jlink was not found")
        jlink = pathlib.Path(discovered)
    run([jlink, "--add-modules", "java.base,java.logging,java.smartcardio,jdk.crypto.ec",
         "--strip-debug", "--no-man-pages", "--no-header-files", "--output", stage / "runtime"], env=env)

    if system == "windows":
        (stage / "microcard-wallet.cmd").write_text(
            '@echo off\r\n"%~dp0runtime\\bin\\java.exe" -cp "%~dp0wallet\\microcard-wallet.jar;%~dp0wallet\\lib\\*" dev.mistial.microcard.wallet.Main %*\r\n',
            encoding="ascii")
    else:
        launcher = stage / "microcard-wallet"
        launcher.write_text("""#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$ROOT/runtime/bin/java" -cp "$ROOT/wallet/microcard-wallet.jar:$ROOT/wallet/lib/*" dev.mistial.microcard.wallet.Main "$@"
""", encoding="utf-8")
        launcher.chmod(0o755)

    for name in ("README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / name, stage / name)
    for name in ("ARCHITECTURE.md", "WALLET.md", "STATUS.md", "ROADMAP.md"):
        shutil.copy2(ROOT / "docs" / name, stage / name)

    analyzer_output = stage / "sdk"
    analyzer_output.mkdir()
    run(["dotnet", "pack", "managed/MicroCard.Analyzers", "-c", "Release", "-o", analyzer_output,
         "--nologo"], env=env)

    objcopy = shutil.which("arm-none-eabi-objcopy") or shutil.which("rust-objcopy")
    if objcopy is None:
        raise RuntimeError("arm-none-eabi-objcopy or rust-objcopy is required")
    for engine in ("mc04", "jcvm"):
        board_output = stage / f"nrf52840-{engine}-development"
        board_output.mkdir()
        run(["cargo", "build", "--release", "--locked", "--features", f"engine-{engine}"],
            env=env, cwd=ROOT / "board/nrf52840")
        board_elf = ROOT / "board/nrf52840/target/thumbv7em-none-eabihf/release/microcard-nrf52840"
        shutil.copy2(board_elf, board_output / f"microcard-{engine}.elf")
        run([objcopy, "-O", "ihex", board_elf, board_output / f"microcard-{engine}.hex"], env=env)

    metadata = {
        "version": VERSION,
        "platform": platform_name,
        "python": platform.python_version(),
        "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    }
    (stage / "BUILD.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    checksums = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(stage).as_posix()}\n")
    (stage / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")

    archive = shutil.make_archive(str(artifact_root / stage.name), "gztar", stage.parent, stage.name)
    digest = hashlib.sha256(pathlib.Path(archive).read_bytes()).hexdigest()
    print(f"Created {archive}\nSHA-256 {digest}")


if __name__ == "__main__":
    main()
