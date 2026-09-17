#!/usr/bin/env python3
"""Build and measure the opt-in nRF52840 CC310 platform providers."""

import argparse
import difflib
import json
import pathlib
import re
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOARD = ROOT / "board/nrf52840"
BINARY = BOARD / "target/thumbv7em-none-eabihf/release/microcard-nrf52840"
EVIDENCE = ROOT / "docs/NRF52840_CC310_PLATFORM_SPIKE.json"
SHA256_SYMBOLS = {
    "nrf_cc3xx_platform_init_no_rng",
    "nrf_cc3xx_platform_set_abort",
    "nrf_cc3xx_platform_sha256_hash",
}
ENTROPY_SYMBOLS = {
    "nrf_cc3xx_platform_init",
    "nrf_cc3xx_platform_entropy_get",
    "nrf_cc3xx_platform_set_abort",
    "nrf_cc3xx_platform_sha256_hash",
}
MAC_DRIVER_SYMBOLS = ENTROPY_SYMBOLS | {
    "cc3xx_mac_abort",
    "cc3xx_mac_sign_finish",
    "cc3xx_mac_sign_setup",
    "cc3xx_mac_update",
    "microcard_cc310_mac_update",
    "psa_driver_wrapper_mac_abort",
    "psa_driver_wrapper_mac_sign_finish",
    "psa_driver_wrapper_mac_sign_setup",
    "psa_driver_wrapper_mac_update",
}
CMAC_SYMBOLS = MAC_DRIVER_SYMBOLS | {
    "microcard_cc310_cmac_begin",
    "microcard_cc310_cmac_finish",
}
HMAC_SYMBOLS = MAC_DRIVER_SYMBOLS | {
    "microcard_cc310_hmac_sha256_begin",
    "microcard_cc310_hmac_sha256_finish",
}
AES_SYMBOLS = ENTROPY_SYMBOLS | {
    "cc3xx_cipher_encrypt",
    "cc3xx_cipher_finish",
    "cc3xx_cipher_set_iv",
    "cc3xx_cipher_update",
    "microcard_cc310_aes128_encrypt_block",
    "psa_driver_wrapper_cipher_encrypt",
}
CBC_SYMBOLS = AES_SYMBOLS | {
    "cc3xx_cipher_abort",
    "cc3xx_cipher_decrypt_setup",
    "cc3xx_cipher_encrypt_setup",
    "microcard_cc310_aes128_cbc_in_place",
    "psa_driver_wrapper_cipher_abort",
    "psa_driver_wrapper_cipher_decrypt_setup",
    "psa_driver_wrapper_cipher_encrypt_setup",
    "psa_driver_wrapper_cipher_finish",
    "psa_driver_wrapper_cipher_set_iv",
    "psa_driver_wrapper_cipher_update",
}
CCM_SYMBOLS = AES_SYMBOLS | {
    "cc3xx_aead_decrypt",
    "cc3xx_aead_encrypt",
    "microcard_cc310_aes128_ccm_decrypt",
    "microcard_cc310_aes128_ccm_encrypt",
    "psa_driver_wrapper_aead_decrypt",
    "psa_driver_wrapper_aead_encrypt",
}
P256_SYMBOLS = ENTROPY_SYMBOLS | {
    "cc3xx_ecdh_calc_secret_wrst",
    "cc3xx_internal_ecdsa_sign",
    "cc3xx_internal_ecdsa_verify",
    "cc3xx_internal_export_ecc_wrst_public_key",
    "cc3xx_key_agreement",
    "cc3xx_sign_hash",
    "cc3xx_verify_hash",
    "microcard_cc310_p256_ecdh",
    "microcard_cc310_p256_public_key",
    "microcard_cc310_p256_sign_hash",
    "microcard_cc310_p256_verify_hash",
}


def tool(name):
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"{name} is required")
    return path


def measure(extra_arguments):
    subprocess.run(
        ["cargo", "build", "--release", "--locked", *extra_arguments],
        cwd=BOARD,
        check=True,
    )
    output = subprocess.run(
        [tool("arm-none-eabi-size"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fields = output.strip().splitlines()[-1].split()
    return {
        "text_bytes": int(fields[0]),
        "data_bytes": int(fields[1]),
        "bss_bytes": int(fields[2]),
    }


def linked_symbols():
    output = subprocess.run(
        [tool("arm-none-eabi-nm"), "-g", str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {line.split()[-1] for line in output.splitlines() if line.split()}


def provider_stack_evidence(method, frame_patterns, frame_bytes, peak_bytes):
    symbols = subprocess.run(
        [tool("arm-none-eabi-nm"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    candidates = [
        line.split()[-1]
        for line in symbols.splitlines()
        if "microcard_nrf52840" in line and method in line
    ]
    if len(candidates) != 1:
        raise SystemExit(f"cannot identify the linked nRF52840 {method} provider frame")
    disassembly = subprocess.run(
        [tool("arm-none-eabi-objdump"), "-d", f"--disassemble={candidates[0]}", str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    patterns = [r"push\s+\{r4, r5, r6, r7, lr\}", *frame_patterns]
    if any(re.search(pattern, disassembly) is None for pattern in patterns):
        raise SystemExit(f"linked nRF52840 {method} provider stack frame changed")
    return {
        "multipart_state_bytes": 544,
        "rust_frame_with_saved_registers_bytes": frame_bytes,
        "maximum_nested_shim_bytes": 64,
        "bridge_peak_bytes": peak_bytes,
        "vendor_internal_high_water_measured": False,
    }


def aes_stack_evidence():
    symbols = subprocess.run(
        [tool("arm-none-eabi-nm"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    candidates = [
        line.split()[-1]
        for line in symbols.splitlines()
        if "microcard_nrf52840" in line and "aes128_encrypt_block_in_place" in line
    ]
    if len(candidates) != 1:
        raise SystemExit("cannot identify the linked nRF52840 AES-128 provider frame")
    disassembly = subprocess.run(
        [tool("arm-none-eabi-objdump"), "-d", f"--disassemble={candidates[0]}", str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for pattern in [
        r"push\s+\{r4, r5, r6, r7, lr\}",
        r"str\.w\s+fp, \[sp, #-4\]!",
        r"sub\s+sp, #24",
    ]:
        if re.search(pattern, disassembly) is None:
            raise SystemExit("linked nRF52840 AES-128 provider stack frame changed")
    return {
        "local_result_bytes": 16,
        "rust_frame_with_saved_registers_bytes": 48,
        "maximum_nested_shim_bytes": 88,
        "bridge_peak_bytes": 136,
        "vendor_internal_high_water_measured": False,
    }


def cbc_stack_evidence():
    symbols = subprocess.run(
        [tool("arm-none-eabi-nm"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    cases = {
        "aes_cbc_encrypt": [
            r"push\s+\{r4, r5, r6, r7, lr\}",
            r"stmdb\s+sp!, \{r8, r9, sl, fp\}",
            r"sub\s+sp, #12",
        ],
        "aes_cbc_decrypt": [
            r"push\s+\{r4, r5, r6, r7, lr\}",
            r"stmdb\s+sp!, \{r8, r9, (?:sl|fp)\}",
            r"sub\s+sp, #16",
        ],
    }
    for method, patterns in cases.items():
        candidates = [
            line.split()[-1]
            for line in symbols.splitlines()
            if "microcard_nrf52840" in line and method in line
        ]
        if len(candidates) != 1:
            raise SystemExit(f"cannot identify the linked nRF52840 {method} frame")
        disassembly = subprocess.run(
            [
                tool("arm-none-eabi-objdump"),
                "-d",
                f"--disassemble={candidates[0]}",
                str(BINARY),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if any(re.search(pattern, disassembly) is None for pattern in patterns):
            raise SystemExit(f"linked nRF52840 {method} stack frame changed")
    return {
        "rust_frame_with_saved_registers_bytes": 48,
        "maximum_nested_shim_bytes": 384,
        "bridge_peak_bytes": 432,
        "vendor_internal_high_water_measured": False,
    }


def ccm_stack_evidence():
    symbols = subprocess.run(
        [tool("arm-none-eabi-nm"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    evidence = {}
    for method in ("aes_ccm_encrypt", "aes_ccm_decrypt"):
        candidates = [
            line.split()[-1]
            for line in symbols.splitlines()
            if "microcard_nrf52840" in line and method in line
        ]
        if len(candidates) != 1:
            raise SystemExit(f"cannot identify the linked nRF52840 {method} frame")
        disassembly = subprocess.run(
            [
                tool("arm-none-eabi-objdump"),
                "-d",
                f"--disassemble={candidates[0]}",
                str(BINARY),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        frame = re.search(r"sub(?:\.w)?\s+sp, (?:sp, )?#(\d+)", disassembly)
        if (
            re.search(r"push\s+\{r4, r5, r6, r7, lr\}", disassembly) is None
            or re.search(r"stmdb\s+sp!, \{r8, r9, (?:sl|fp)\}", disassembly) is None
            or frame is None
        ):
            raise SystemExit(f"linked nRF52840 {method} stack frame changed")
        evidence[method] = {
            "rust_frame_with_saved_registers_bytes": int(frame.group(1)) + 32,
            "maximum_nested_shim_bytes": 112,
            "bridge_peak_bytes": int(frame.group(1)) + 144,
            "vendor_internal_high_water_measured": False,
        }
    return evidence


def p256_stack_evidence():
    symbols = subprocess.run(
        [tool("arm-none-eabi-nm"), str(BINARY)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    cases = {
        "p256_public_key_into": (
            24,
            64,
            [
                r"push\s+\{r4, r5, r6, r7, lr\}",
                r"str\.w\s+fp, \[sp, #-4\]!",
            ],
        ),
        "p256_ecdh_into": (
            40,
            88,
            [
                r"push\s+\{r4, r5, r6, r7, lr\}",
                r"stmdb\s+sp!, \{r8, r9, fp\}",
                r"sub\s+sp, #8",
            ],
        ),
        "p256_ecdsa_sign_into": (
            72,
            80,
            [
                r"push\s+\{r4, r5, r6, r7, lr\}",
                r"stmdb\s+sp!, \{r8, r9, (?:sl|fp)\}",
                r"sub\s+sp, #40",
            ],
        ),
        "p256_ecdsa_verify": (
            72,
            80,
            [
                r"push\s+\{r4, r5, r6, r7, lr\}",
                r"stmdb\s+sp!, \{r8, r9, sl\}",
                r"sub\s+sp, #40",
            ],
        ),
    }
    evidence = {}
    for method, (rust_frame, shim_frame, patterns) in cases.items():
        candidates = [
            line.split()[-1]
            for line in symbols.splitlines()
            if "microcard_nrf52840" in line and method in line
        ]
        if len(candidates) != 1:
            raise SystemExit(f"cannot identify the linked nRF52840 {method} frame")
        disassembly = subprocess.run(
            [
                tool("arm-none-eabi-objdump"),
                "-d",
                f"--disassemble={candidates[0]}",
                str(BINARY),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if any(re.search(pattern, disassembly) is None for pattern in patterns):
            raise SystemExit(f"linked nRF52840 {method} stack frame changed")
        evidence[method] = {
            "rust_frame_with_saved_registers_bytes": rust_frame,
            "maximum_nested_shim_bytes": shim_frame,
            "bridge_peak_bytes": rust_frame + shim_frame,
            "vendor_internal_high_water_measured": False,
        }
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    subprocess.run(
        [sys.executable, str(ROOT / "scripts/verify_nrf_crypto_sources.py")],
        cwd=ROOT,
        check=True,
    )
    baseline = measure([])
    sha256 = measure(["--features", "cc310-sha256"])
    missing = SHA256_SYMBOLS - linked_symbols()
    if missing:
        raise SystemExit(f"CC310 SHA-256 feature is missing linked symbols: {sorted(missing)}")
    entropy = measure(["--features", "cc310-entropy"])
    missing = ENTROPY_SYMBOLS - linked_symbols()
    if missing:
        raise SystemExit(f"CC310 entropy feature is missing linked symbols: {sorted(missing)}")
    cmac = measure(["--features", "cc310-cmac"])
    cmac_symbols = linked_symbols()
    missing = CMAC_SYMBOLS - cmac_symbols
    if missing:
        raise SystemExit(f"CC310 CMAC feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & cmac_symbols
    if allocators:
        raise SystemExit(f"CC310 CMAC feature links C allocators: {sorted(allocators)}")
    cmac_stack = provider_stack_evidence(
        "aes_cmac_parts_into",
        [r"stmdb\s+sp!, \{r8, r9, (?:sl|fp)\}", r"sub\.w\s+sp, sp, #560"],
        592,
        656,
    )
    hmac = measure(["--features", "cc310-hmac"])
    hmac_symbols = linked_symbols()
    missing = HMAC_SYMBOLS - hmac_symbols
    if missing:
        raise SystemExit(f"CC310 HMAC feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & hmac_symbols
    if allocators:
        raise SystemExit(f"CC310 HMAC feature links C allocators: {sorted(allocators)}")
    hmac_stack = provider_stack_evidence(
        "hmac_sha256_into",
        [r"stmdb\s+sp!, \{r8, r9, fp\}", r"sub\.w\s+sp, sp, #576"],
        608,
        672,
    )
    aes = measure(["--features", "cc310-aes"])
    aes_symbols = linked_symbols()
    missing = AES_SYMBOLS - aes_symbols
    if missing:
        raise SystemExit(f"CC310 AES feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & aes_symbols
    if allocators:
        raise SystemExit(f"CC310 AES feature links C allocators: {sorted(allocators)}")
    aes_stack = aes_stack_evidence()
    cbc = measure(["--features", "cc310-cbc"])
    cbc_symbols = linked_symbols()
    missing = CBC_SYMBOLS - cbc_symbols
    if missing:
        raise SystemExit(f"CC310 CBC feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & cbc_symbols
    if allocators:
        raise SystemExit(f"CC310 CBC feature links C allocators: {sorted(allocators)}")
    cbc_stack = cbc_stack_evidence()
    ccm = measure(["--features", "cc310-ccm"])
    ccm_symbols = linked_symbols()
    missing = CCM_SYMBOLS - ccm_symbols
    if missing:
        raise SystemExit(f"CC310 CCM feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & ccm_symbols
    if allocators:
        raise SystemExit(f"CC310 CCM feature links C allocators: {sorted(allocators)}")
    ccm_stack = ccm_stack_evidence()
    p256 = measure(["--features", "cc310-p256"])
    p256_symbols = linked_symbols()
    missing = P256_SYMBOLS - p256_symbols
    if missing:
        raise SystemExit(f"CC310 P-256 feature is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & p256_symbols
    if allocators:
        raise SystemExit(f"CC310 P-256 feature links C allocators: {sorted(allocators)}")
    p256_stack = p256_stack_evidence()
    combined = measure(
        ["--features", "cc310-cmac,cc310-hmac,cc310-cbc,cc310-ccm,cc310-p256"]
    )
    combined_symbols = linked_symbols()
    missing = (
        CMAC_SYMBOLS | HMAC_SYMBOLS | CBC_SYMBOLS | CCM_SYMBOLS | P256_SYMBOLS
    ) - combined_symbols
    if missing:
        raise SystemExit(f"combined CC310 feature set is missing linked symbols: {sorted(missing)}")
    allocators = {"malloc", "calloc", "realloc", "free"} & combined_symbols
    if allocators:
        raise SystemExit(f"combined CC310 feature set links C allocators: {sorted(allocators)}")
    provider_stack_evidence(
        "aes_cmac_parts_into",
        [r"stmdb\s+sp!, \{r8, r9, (?:sl|fp)\}", r"sub\.w\s+sp, sp, #560"],
        592,
        656,
    )
    provider_stack_evidence(
        "hmac_sha256_into",
        [r"stmdb\s+sp!, \{r8, r9, fp\}", r"sub\.w\s+sp, sp, #576"],
        608,
        672,
    )
    aes_stack_evidence()
    cbc_stack_evidence()
    ccm_stack_evidence()
    p256_stack_evidence()

    ceilings = {"text_bytes": 375_000, "total_ram_bytes": 200_000}
    for name, measured in (
        ("SHA-256", sha256),
        ("entropy", entropy),
        ("CMAC", cmac),
        ("HMAC", hmac),
        ("AES", aes),
        ("CBC", cbc),
        ("CCM", ccm),
        ("P-256", p256),
        ("combined", combined),
    ):
        if measured["text_bytes"] > ceilings["text_bytes"]:
            raise SystemExit(f"CC310 {name} build exceeds its flash ceiling")
        if measured["data_bytes"] + measured["bss_bytes"] > ceilings["total_ram_bytes"]:
            raise SystemExit(f"CC310 {name} build exceeds its aggregate RAM ceiling")

    def delta(measured):
        return {
            name: measured[name] - baseline[name]
            for name in ("text_bytes", "data_bytes", "bss_bytes")
        }

    result = {
        "format": 1,
        "target": "thumbv7em-none-eabihf",
        "features": [
            "cc310-sha256",
            "cc310-entropy",
            "cc310-cmac",
            "cc310-hmac",
            "cc310-aes",
            "cc310-cbc",
            "cc310-ccm",
            "cc310-p256",
        ],
        "default_enabled": False,
        "physical_known_answer_passed": False,
        "boot_self_tests": [
            "SHA-256 empty input",
            "SHA-256 flash-backed abc input",
            "SHA-256 RAM-backed abc input",
            "two nonconstant distinct 256-bit entropy samples",
            "RFC 4493 AES-CMAC examples 1 through 4 with multipart and RAM-backed input",
            "RFC 4231 HMAC-SHA-256 case 1 with RAM-backed input",
            "HMAC-SHA-256 empty key and empty input",
            "FIPS 197 AES-128 block encryption example",
            "NIST SP 800-38A AES-128-CBC first-block encrypt and decrypt",
            "NIST CAVP AES-128-CCM encrypt, decrypt and modified-tag rejection",
            "RFC 6979 P-256 public key, deterministic ECDSA signature and verification",
            "P-256 ECDSA changed-message rejection",
            "P-256 ECDH fixed shared secret",
        ],
        "baseline": baseline,
        "variants": {
            "sha256": {"size": sha256, "delta": delta(sha256)},
            "entropy": {"size": entropy, "delta": delta(entropy)},
            "cmac": {"size": cmac, "delta": delta(cmac)},
            "hmac": {"size": hmac, "delta": delta(hmac)},
            "aes": {"size": aes, "delta": delta(aes)},
            "cbc": {"size": cbc, "delta": delta(cbc)},
            "ccm": {"size": ccm, "delta": delta(ccm)},
            "p256": {"size": p256, "delta": delta(p256)},
            "combined": {"size": combined, "delta": delta(combined)},
        },
        "ceilings": ceilings,
        "required_symbols": {
            "sha256": sorted(SHA256_SYMBOLS),
            "entropy": sorted(ENTROPY_SYMBOLS),
            "cmac": sorted(CMAC_SYMBOLS),
            "hmac": sorted(HMAC_SYMBOLS),
            "aes": sorted(AES_SYMBOLS),
            "cbc": sorted(CBC_SYMBOLS),
            "ccm": sorted(CCM_SYMBOLS),
            "p256": sorted(P256_SYMBOLS),
        },
        "cmac_stack": cmac_stack,
        "hmac_stack": hmac_stack,
        "aes_stack": aes_stack,
        "cbc_stack": cbc_stack,
        "ccm_stack": ccm_stack,
        "p256_stack": p256_stack,
        "combined_stack_shapes_verified": True,
        "forbidden_c_allocator_symbols": ["calloc", "free", "malloc", "realloc"],
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.check:
        current = EVIDENCE.read_text()
        if current != encoded:
            difference = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(EVIDENCE),
                    tofile="fresh measurement",
                )
            )
            raise SystemExit(f"CC310 platform spike evidence is stale:\n{difference}")
    else:
        EVIDENCE.write_text(encoded)
    print(
        "PASS: opt-in CC310 SHA-256, entropy, AES-CMAC, HMAC-SHA-256, AES-128, CBC, CCM and P-256 providers link; "
        f"P-256 delta {result['variants']['p256']['delta']['text_bytes']} flash bytes and "
        f"{result['variants']['p256']['delta']['data_bytes'] + result['variants']['p256']['delta']['bss_bytes']} RAM bytes"
    )


if __name__ == "__main__":
    main()
