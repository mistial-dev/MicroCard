#!/usr/bin/env python3
"""Explicit coverage-guided campaigns with retained logs and reproducible seeds."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import time
import signal

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target", choices=["boundaries", "signed_packages", "crypto_arguments", "domain_sequences"])
    p.add_argument("--seconds", type=int, required=True,
                   help="explicit campaign duration; sustained runs are never an implicit default")
    p.add_argument("--sanitizer", choices=["address", "none"], default="address")
    p.add_argument("--toolchain", default="nightly-2026-09-19")
    a = p.parse_args()
    if a.seconds <= 0: p.error("seconds must be positive")
    tool = ROOT / "work/fuzz-tools/bin/cargo-fuzz"
    if not tool.exists(): p.error("Install cargo-fuzz with cargo install cargo-fuzz --locked --root work/fuzz-tools")
    output = ROOT / "artifacts/fuzz" / (a.target + "-" + str(time.time_ns()))
    output.mkdir(parents=True)
    corpus = output / "input-corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    if a.target == "signed_packages":
        (corpus / "ret").write_bytes(bytes([1,20]))
        (corpus / "integer").write_bytes(bytes([1,1,42,0,0,0,19,20]))
        if (ROOT / "work/counter.mca").exists():
            (corpus / "counter-mc04").write_bytes(b"\0" + (ROOT / "work/counter.mca").read_bytes())
    elif a.target == "boundaries":
        (corpus / "apdu").write_bytes(bytes.fromhex("8050000008000000000000000000"))
        if (ROOT / "fuzz/fixtures/counter.mca").exists():
            (corpus / "assembly").write_bytes((ROOT / "fuzz/fixtures/counter.mca").read_bytes())
    elif a.target == "crypto_arguments":
        (corpus / "empty").write_bytes(b"")
        (corpus / "block").write_bytes(bytes(range(32)))
    else:
        (corpus / "lifecycle").write_bytes(bytes(range(40)))
        (corpus / "faults").write_bytes(b"S" + bytes([8, 0, 0, 7]) * 8)
        crypto = bytearray([0])
        for command in range(6):
            crypto.extend([0, 3, command, 0, 0])  # Invoke KeyOperations.
        for command in range(6):
            crypto.extend([0, 5, command, 0, 0])  # Invoke BlobRecords.
        crypto.extend([0, 7, 1, 0xaa, 0xbb])  # Invoke the Kdf108 consumer.
        (corpus / "crypto-services").write_bytes(crypto)
        (corpus / "dependency-replacement").write_bytes(
            bytes([0, 10, 0, 0, 0, 0, 11, 0, 0, 0, 0])
        )
    # libFuzzer writes new discoveries to its first corpus directory. Additional
    # corpora remain inputs, so retain prior discoveries without sharing writes.
    inputs = [str(corpus)]
    retained = ROOT / "fuzz/corpus" / a.target
    if retained.is_dir(): inputs.append(str(retained))
    seeds = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in corpus.iterdir()}
    command = [str(tool), "run", "--sanitizer", a.sanitizer, a.target, *inputs, "--", f"-max_total_time={a.seconds}",
               "-max_len=4096", "-timeout=5", "-rss_limit_mb=1024", "-print_final_stats=1"]
    info = dict(target=a.target, command=command, toolchain=a.toolchain, sanitizer=a.sanitizer,
                input_corpora=inputs, seed_sha256=seeds,
                revision=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
                dirty=bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
                target_sha256=hashlib.sha256((ROOT/f"fuzz/fuzz_targets/{a.target}.rs").read_bytes()).hexdigest(),
                lock_sha256=hashlib.sha256((ROOT/"fuzz/Cargo.lock").read_bytes()).hexdigest())
    start=time.monotonic()
    with (output / "run.log").open("w") as log:
        process=subprocess.Popen(command,cwd=ROOT,env={**os.environ,"RUSTUP_TOOLCHAIN":a.toolchain},stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            code=process.wait(timeout=a.seconds+180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code=124
    info.update(exit_code=code,elapsed_seconds=time.monotonic()-start,
                corpus_files=len(list(corpus.iterdir())))
    (output/"result.json").write_text(json.dumps(info,indent=2)+"\n")
    print((output/"run.log").read_text()[-4000:])
    print(f"Evidence: {output}")
    raise SystemExit(code)

if __name__ == "__main__": main()
