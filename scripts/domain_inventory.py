#!/usr/bin/env python3
"""Read public SSD metadata over SCP03. Does not delete, load or reset anything."""
import argparse
import json
from dk_smoke import SerialClient

MAX_DOMAIN_RECORDS = 9  # ISD plus the eight-SSD profile limit.

def parse_policy(raw):
    if len(raw) != 19 or raw[0] != 1: raise ValueError("invalid policy")
    bits=int.from_bytes(raw[1:9],"little")
    return dict(capabilities=[bit for bit in range(64) if bits&(1<<bit)],
                max_assemblies=raw[9],max_instances=raw[10],
                max_int_records=int.from_bytes(raw[11:13],"little"),max_blob_records=raw[13],
                max_blob_bytes=int.from_bytes(raw[14:16],"little"),max_key_slots=raw[16],
                max_package_bytes=int.from_bytes(raw[17:19],"little"))

def inventory(client):
    result = []
    index = 0
    total = None
    while True:
        raw = client.command(0xe2, bytes([index]))
        if len(raw) < 4 or raw[0] != 1 or raw[2] != index:
            raise ValueError("invalid inventory header")
        if total is None: total = raw[1]
        if not 1 <= total <= MAX_DOMAIN_RECORDS or raw[1] != total: raise ValueError("inventory changed; retry")
        n = raw[3]
        if not 1 <= n <= 64 or len(raw) != 57+n: raise ValueError("invalid inventory length")
        start = 4+n
        bound = raw[start+16]
        if bound not in (0,1): raise ValueError("invalid binding flag")
        record = dict(identifier=raw[4:start].decode(), incarnation=raw[start:start+16].hex(),
                      bound=bool(bound), signing_public_key=raw[start+17:start+49].hex() if bound else None,
                      assemblies=raw[start+49], instances=raw[start+50],
                      application_records=int.from_bytes(raw[start+51:start+53], "little"))
        record["policy"]=parse_policy(client.command(0xe3,record["identifier"].encode()))
        if index == 0 and record["identifier"] != "ISD": raise ValueError("missing ISD inventory record")
        if index > 1 and record["identifier"] <= result[-1]["identifier"]: raise ValueError("inventory changed; retry")
        result.append(record)
        index += 1
        if index == total: return result

def empty_bound_candidates(records, prefix):
    """Return diagnostic candidates only; inventory cannot authorize deletion."""
    return [record for record in records
            if record["identifier"] != "ISD" and record["identifier"].startswith(prefix)
            and record["bound"] and record["assemblies"] == 0 and record["instances"] == 0
            and record["application_records"] == 0]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port",required=True);p.add_argument("--management-key",required=True)
    p.add_argument("--empty-prefix", help="Show empty bound diagnostic candidates with this ID prefix")
    a=p.parse_args();c=SerialClient(a.management_key,a.port)
    try:
        c.connect();records=inventory(c)
        if a.empty_prefix is not None: records=empty_bound_candidates(records,a.empty_prefix)
        print(json.dumps(records,indent=2))
    finally:c.close()

if __name__ == "__main__":main()
