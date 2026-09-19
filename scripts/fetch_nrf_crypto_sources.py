#!/usr/bin/env python3
"""Fetch the pinned CC310 build inputs; preserve and verify existing checkouts."""
import argparse
import json
import pathlib
import subprocess
import tempfile
from verify_nrf_crypto_sources import (
    ROOT, DEFAULT_LOCK, DEFAULT_CHECKOUT, DEFAULT_NRFXLIB_LOCK,
    DEFAULT_NRFXLIB_CHECKOUT, DEFAULT_SDK_NRF_LOCK, DEFAULT_SDK_NRF_CHECKOUT,
    verify_checkout,
)

SOURCES = (
    (DEFAULT_LOCK, DEFAULT_CHECKOUT.name,
     ("include", "core", "dispatch", "oberon/platforms/nordic_nrf", "oberon/drivers")),
    (DEFAULT_NRFXLIB_LOCK, DEFAULT_NRFXLIB_CHECKOUT.name,
     ("crypto/nrf_cc310_platform", "crypto/nrf_cc310_mbedcrypto")),
    (DEFAULT_SDK_NRF_LOCK, DEFAULT_SDK_NRF_CHECKOUT.name,
     ("subsys/nrf_security/src/drivers/nrf_cc3xx",)),
)


def fetch(directory, lock_path, name, paths):
    destination = directory / name
    if destination.exists():
        verify_checkout(destination, lock_path)
        print(f"Verified existing {name}", flush=True)
        return
    source = json.loads(lock_path.read_text())["source"]
    # Publish only verified inputs. Failed downloads never leave a partial destination.
    with tempfile.TemporaryDirectory(prefix=".crypto-fetch-", dir=directory) as temporary:
        checkout = pathlib.Path(temporary) / "checkout"
        subprocess.run([
            "git", "-c", "core.autocrlf=false", "clone", "--filter=blob:none",
            "--depth", "1", "--single-branch", "--no-checkout", "--branch", source["tag"],
            source["repository"], str(checkout),
        ], check=True)
        def git(*arguments):
            subprocess.run(["git", "-C", str(checkout), *arguments], check=True)
        git("config", "core.autocrlf", "false")
        git("sparse-checkout", "set", "--cone", *paths)
        git("checkout", "--detach", source["commit"])
        verify_checkout(checkout, lock_path)
        checkout.rename(destination)
    print(f"Fetched and verified {name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=pathlib.Path, default=ROOT / "work")
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    for lock, name, paths in SOURCES:
        fetch(directory, lock, name, paths)


if __name__ == "__main__":
    main()
