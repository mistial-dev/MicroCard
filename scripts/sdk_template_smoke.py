#!/usr/bin/env python3
"""Pack and exercise the SDK and microcard-assembly template in isolation."""

import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "0.1.0-wip"


def run(*args: str, cwd: pathlib.Path, env: dict[str, str]) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", default="Release")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="microcard-sdk-") as temporary:
        work = pathlib.Path(temporary)
        feed = work / "feed"
        feed.mkdir()
        environment = {
            **os.environ,
            "DOTNET_CLI_HOME": str(work / "dotnet-home"),
            "NUGET_PACKAGES": str(work / "packages"),
            "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        }
        pack_environment = {
            **os.environ,
            "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        }

        for project in (
            "managed/OpenPhysical.MicroCard.Sdk/OpenPhysical.MicroCard.Sdk.csproj",
            "managed/OpenPhysical.MicroCard.Templates/OpenPhysical.MicroCard.Templates.csproj",
        ):
            run("dotnet", "pack", str(ROOT / project), "-c", args.configuration,
                "-o", str(feed), "--nologo", cwd=ROOT, env=pack_environment)

        sdk_package = feed / f"OpenPhysical.MicroCard.Sdk.{VERSION}.nupkg"
        template_package = feed / f"OpenPhysical.MicroCard.Templates.{VERSION}.nupkg"
        required = {
            "ref/net10.0/MicroCard.AppModel.dll",
            "ref/net10.0/MicroCard.AppModel.xml",
            "analyzers/dotnet/cs/MicroCard.Analyzers.dll",
            "tools/net10.0/any/MicroCard.Tool.dll",
            "buildTransitive/OpenPhysical.MicroCard.Sdk.props",
            "buildTransitive/OpenPhysical.MicroCard.Sdk.targets",
        }
        with zipfile.ZipFile(sdk_package) as archive:
            missing = required.difference(archive.namelist())
        if missing:
            raise RuntimeError(f"SDK package is missing: {sorted(missing)}")

        hive = work / "template-hive"
        run("dotnet", "new", "install", str(template_package),
            "--debug:custom-hive", str(hive), cwd=work, env=environment)
        project = work / "CredentialCard"
        run("dotnet", "new", "microcard-assembly", "-n", project.name,
            "--sdkVersion", VERSION, "--debug:custom-hive", str(hive),
            "-o", str(project), cwd=work, env=environment)
        project_file = project / f"{project.name}.csproj"
        if project_file.read_text(encoding="utf-8").count("<PackageReference") != 1:
            raise RuntimeError("Generated project must contain exactly one package reference")

        nuget_config = work / "NuGet.Config"
        nuget_config.write_text(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<configuration><packageSources><clear />"
            f"<add key=\"local\" value=\"{feed}\" />"
            "</packageSources></configuration>\n",
            encoding="utf-8",
        )
        run("dotnet", "restore", str(project), "--configfile", str(nuget_config),
            "--nologo", cwd=work, env=environment)
        run("dotnet", "build", str(project), "--no-restore", "--nologo",
            cwd=work, env=environment)

        prefix = project / "obj/Debug/net10.0/microcard/CredentialCard"
        for suffix in (".mca", ".json", ".map.json"):
            if not prefix.with_suffix(suffix).is_file():
                raise RuntimeError(f"Missing converted output: {prefix.with_suffix(suffix)}")
        manifest = json.loads(prefix.with_suffix(".json").read_text(encoding="utf-8"))
        if manifest["dependencies"]:
            raise RuntimeError("Compile-time application model became a device dependency")
        if list((project / "bin").rglob("MicroCard.AppModel.dll")):
            raise RuntimeError("Compile-time application model was copied to the build output")

        print("PASS: SDK package and microcard-assembly template")


if __name__ == "__main__":
    main()
