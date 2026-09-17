#!/usr/bin/env python3
"""Verify the locally inspected Nordic crypto source against its project pin."""

import argparse
import hashlib
import json
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "board/nrf52840/oberon-psa-crypto-ncs-v3.4.0.lock.json"
DEFAULT_CHECKOUT = ROOT / "work/sdk-oberon-psa-crypto-ncs-v3.4.0"
DEFAULT_NRFXLIB_LOCK = ROOT / "board/nrf52840/nrfxlib-3.4.0.lock.json"
DEFAULT_NRFXLIB_CHECKOUT = ROOT / "work/nrfxlib-v3.4.0"
DEFAULT_SDK_NRF_LOCK = ROOT / "board/nrf52840/sdk-nrf-3.4.0.lock.json"
DEFAULT_SDK_NRF_CHECKOUT = ROOT / "work/sdk-nrf-v3.4.0"


def git(checkout, *arguments):
    result = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def check_digest(checkout, entry):
    path = checkout / entry["path"]
    try:
        contents = path.read_bytes()
    except FileNotFoundError as error:
        raise SystemExit(f"missing pinned source: {entry['path']}") from error
    actual = hashlib.sha256(contents).hexdigest()
    if actual != entry["sha256"]:
        raise SystemExit(f"digest mismatch: {entry['path']}")
    if "bytes" in entry and len(contents) != entry["bytes"]:
        raise SystemExit(f"size mismatch: {entry['path']}")


def check_git_identity(checkout, expected):
    checks = {
        "commit": git(checkout, "rev-parse", "HEAD"),
        "tree": git(checkout, "rev-parse", "HEAD^{tree}"),
        "tag_object": git(checkout, "rev-parse", f"refs/tags/{expected['tag']}"),
    }
    for name, actual in checks.items():
        if actual != expected[name]:
            raise SystemExit(f"Nordic source {name} mismatch")
    if git(checkout, "status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("Nordic source checkout has modified tracked files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=pathlib.Path, default=DEFAULT_CHECKOUT)
    parser.add_argument("--lock", type=pathlib.Path, default=DEFAULT_LOCK)
    parser.add_argument(
        "--nrfxlib-checkout", type=pathlib.Path, default=DEFAULT_NRFXLIB_CHECKOUT
    )
    parser.add_argument("--nrfxlib-lock", type=pathlib.Path, default=DEFAULT_NRFXLIB_LOCK)
    parser.add_argument(
        "--sdk-nrf-checkout", type=pathlib.Path, default=DEFAULT_SDK_NRF_CHECKOUT
    )
    parser.add_argument("--sdk-nrf-lock", type=pathlib.Path, default=DEFAULT_SDK_NRF_LOCK)
    args = parser.parse_args()

    if not (args.checkout / ".git").exists():
        raise SystemExit(
            "pinned Nordic source checkout is absent; fetch it explicitly into "
            f"{args.checkout} before verification"
        )

    if not (args.nrfxlib_checkout / ".git").exists():
        raise SystemExit(
            "pinned nrfxlib checkout is absent; fetch it explicitly into "
            f"{args.nrfxlib_checkout} before verification"
        )

    if not (args.sdk_nrf_checkout / ".git").exists():
        raise SystemExit(
            "pinned nRF Connect SDK checkout is absent; fetch it explicitly into "
            f"{args.sdk_nrf_checkout} before verification"
        )

    lock = json.loads(args.lock.read_text())
    expected = lock["source"]
    check_git_identity(args.checkout, expected)

    version = (args.checkout / "VERSION").read_text().strip()
    if version != expected["upstream_version"]:
        raise SystemExit("Nordic source VERSION mismatch")

    entries = lock["license_files"] + lock["integration_files"]
    for entry in entries:
        check_digest(args.checkout, entry)

    nrfxlib_lock = json.loads(args.nrfxlib_lock.read_text())
    check_git_identity(args.nrfxlib_checkout, nrfxlib_lock["source"])
    nrfxlib_entries = (
        nrfxlib_lock["artifacts"]
        + nrfxlib_lock["license_files"]
        + nrfxlib_lock["public_headers"]
    )
    for entry in nrfxlib_entries:
        check_digest(args.nrfxlib_checkout, entry)

    sdk_nrf_lock = json.loads(args.sdk_nrf_lock.read_text())
    check_git_identity(args.sdk_nrf_checkout, sdk_nrf_lock["source"])
    sdk_nrf_entries = sdk_nrf_lock["license_files"] + sdk_nrf_lock["integration_files"]
    for entry in sdk_nrf_entries:
        check_digest(args.sdk_nrf_checkout, entry)

    print(
        f"PASS: Nordic Oberon PSA Crypto {expected['tag']} source, licenses, "
        f"and {len(lock['integration_files'])} integration files match the pin; "
        f"nrfxlib {nrfxlib_lock['source']['tag']} archives, licenses, and headers match; "
        f"sdk-nrf {sdk_nrf_lock['source']['tag']} license and "
        f"{len(sdk_nrf_lock['integration_files'])} integration files match"
    )


if __name__ == "__main__":
    main()
