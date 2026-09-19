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


def verify_checkout(checkout, lock_path):
    if not (checkout / ".git").exists():
        raise SystemExit(f"pinned Nordic checkout is absent: {checkout}")
    lock = json.loads(lock_path.read_text())
    expected = lock["source"]
    check_git_identity(checkout, expected)
    if "upstream_version" in expected:
        if (checkout / "VERSION").read_text().strip() != expected["upstream_version"]:
            raise SystemExit("Nordic source VERSION mismatch")
    for group in ("license_files", "integration_files", "artifacts", "public_headers"):
        for entry in lock.get(group, []):
            check_digest(checkout, entry)
    return lock


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

    lock = verify_checkout(args.checkout, args.lock)
    expected = lock["source"]
    nrfxlib_lock = verify_checkout(args.nrfxlib_checkout, args.nrfxlib_lock)
    sdk_nrf_lock = verify_checkout(args.sdk_nrf_checkout, args.sdk_nrf_lock)

    print(
        f"PASS: Nordic Oberon PSA Crypto {expected['tag']} source, licenses, "
        f"and {len(lock['integration_files'])} integration files match the pin; "
        f"nrfxlib {nrfxlib_lock['source']['tag']} archives, licenses, and headers match; "
        f"sdk-nrf {sdk_nrf_lock['source']['tag']} license and "
        f"{len(sdk_nrf_lock['integration_files'])} integration files match"
    )


if __name__ == "__main__":
    main()
