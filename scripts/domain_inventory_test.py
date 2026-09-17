#!/usr/bin/env python3
"""Exercise the complete ISD plus eight-SSD inventory profile on the simulator."""
import os
import pathlib
import subprocess
import tempfile

from domain_inventory import empty_bound_candidates, inventory
from scp03_acceptance import BinaryClient, ROOT, bootstrap_isd


def main():
    subprocess.run(["cargo", "build", "-q", "-p", "microcard-sim"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="microcard-inventory-") as temporary:
        root = pathlib.Path(temporary)
        key = root / "management.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        state = root / "state"
        client = BinaryClient(key, state)
        client.connect()
        bootstrap_isd(client)
        identifiers = [f"inventory-{index}" for index in range(8)]
        for identifier in identifiers:
            assert len(client.command(0xE0, identifier.encode())) == 16
        records = inventory(client)
        assert [record["identifier"] for record in records] == ["ISD", *identifiers]
        assert empty_bound_candidates(records, "inventory-") == []
        candidate = dict(records[1], bound=True)
        assert empty_bound_candidates([records[0], candidate], "inventory-") == [candidate]
        assert empty_bound_candidates([records[0], candidate], "other-") == []
        client.command(0xE0, b"overflow", status=0x6985)
        client.close()

        client = BinaryClient(key, state)
        client.connect()
        assert [record["identifier"] for record in inventory(client)] == ["ISD", *identifiers]
        client.close()
    print("PASS: authenticated inventory accepts ISD plus eight SSD records across reboot")


if __name__ == "__main__":
    main()
