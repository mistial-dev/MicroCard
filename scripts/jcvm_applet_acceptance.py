#!/usr/bin/env python3
"""Drive a real Java Card applet through the simulator.

This is the acceptance run for the Java Card engine. It installs a package, selects it and
sends PIV commands, and checks the applet's own answers rather than the engine's.

A Load File Data Block is a third-party build output and stays out of this repository, so
the path is given on the command line and the script refuses to guess one. Produce a block
with `scripts/jcvm_cap_inventory.py <cap directory> --load-file <out>`.
"""
import argparse
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM = ROOT / "target/debug/microcard-sim"

# The PIV applet AID, NIST SP 800-73-4.
SELECT = "00a4040009a00000030800001000"
# GET DATA for the card capability container, which a blank card does not have.
GET_DATA = "00cb3fff055c035fc107"
# VERIFY the PIV application PIN, padded to eight bytes as the standard requires.
VERIFY_WRONG = "0020008008313233343536ffff"


def exchange(load_file: pathlib.Path, commands: list[str]) -> list[str]:
    result = subprocess.run(
        [str(SIM), "serve-jcvm", str(load_file)],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    return result.stdout.split()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("load_file", type=pathlib.Path,
                        help="a Load File Data Block, as delivered by GlobalPlatform")
    arguments = parser.parse_args()
    if not arguments.load_file.is_file():
        raise SystemExit(f"No load file at {arguments.load_file}")

    answers = exchange(arguments.load_file, [SELECT, GET_DATA, VERIFY_WRONG, VERIFY_WRONG])
    select, get_data, first_pin, second_pin = answers

    # The applet accepted the selection, which means its install registered it and its own
    # select method agreed to be current.
    assert select == "9000", f"SELECT answered {select}"
    # A blank card holds no card capability container, and the applet says so itself.
    assert get_data == "6A82", f"GET DATA answered {get_data}"
    # A wrong PIN answers with the tries that remain, and the count goes down each time,
    # which is the applet's own retry counter surviving from one command to the next.
    assert first_pin.startswith("63C"), f"VERIFY answered {first_pin}"
    assert second_pin.startswith("63C"), f"VERIFY answered {second_pin}"
    assert int(second_pin[3], 16) == int(first_pin[3], 16) - 1, (
        f"retry counter went {first_pin} then {second_pin}"
    )
    print("PASS: Java Card applet installs, selects and answers PIV commands")


if __name__ == "__main__":
    main()
