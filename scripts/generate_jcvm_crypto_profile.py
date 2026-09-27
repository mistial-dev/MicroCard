#!/usr/bin/env python3
"""Generate the proposed JCVM crypto profile from the pinned P71D321 scan."""

import argparse
import json
from pathlib import Path

from jcalgtest_profile import pinned_result


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/JCVM_CRYPTO_PROFILE.json"
CIPHER = "javacardx.crypto.Cipher"
SIGNATURE = "javacard.crypto.Signature"
DIGEST = "javacard.security.MessageDigest"
INITIALIZED = "javacard.security.InitializedMessageDigest"
AGREEMENT = "javacard.security.KeyAgreement"
KEY_BUILDER = "javacard.security.KeyBuilder"


def candidate(kind, name, bits, provider, *, compact=False, factories=None,
              key_types=(), generation=None):
    software = ("tiny_crypto_c" if provider == "tiny_crypto_c"
                or "RSA" in name or name == "ALG_AES_CTR" else "rustcrypto")
    return {
        "kind": kind,
        "algorithm": name,
        "key_bits": bits,
        "provider_candidates": {
            "simulator": software,
            "dk_hardware": provider,
            "dk_software": software,
        },
        "compact_build": "excluded" if compact else "included",
        "factories": factories or {},
        "key_types": list(key_types),
        "generation": generation,
    }


def selections():
    rows = []
    def cipher(name, bits, provider, modern, *, compact=False, key_types=(), generation=None):
        rows.append(candidate("cipher", name, bits, provider, compact=compact,
                              factories={CIPHER: name,
                                         CIPHER + ".getInstance(byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)": modern,
                                         CIPHER + ".OneShot.getInstance(byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)": modern},
                              key_types=key_types, generation=generation))

    for mode in ("CBC", "ECB"):
        for padding, modern_padding in (("NOPAD", "NOPAD"),
                                        ("ISO9797_M1", "ISO9797_M1"),
                                        ("ISO9797_M2", "ISO9797_M2"),
                                        ("PKCS5", "PKCS5")):
            suffix = "BLOCK_128_" if padding == "NOPAD" else ""
            cipher(f"ALG_AES_{suffix}{mode}_{padding}", 128, "cc310",
                   f"CIPHER_AES_{mode} PAD_{modern_padding}",
                   key_types=("TYPE_AES LENGTH_AES_128",))
    cipher("ALG_AES_CTR", 128, "cc310",
           "CIPHER_AES_CTR PAD_NOPAD", key_types=("TYPE_AES LENGTH_AES_128",))
    for mode in ("CBC", "ECB"):
        for padding in ("NOPAD", "ISO9797_M1", "ISO9797_M2", "PKCS5"):
            for bits in (64, 128, 192):
                key_type = {64: "LENGTH_DES", 128: "LENGTH_DES3_2KEY", 192: "LENGTH_DES3_3KEY"}[bits]
                cipher(f"ALG_DES_{mode}_{padding}", bits, "tiny_crypto_c",
                       f"CIPHER_DES_{mode} PAD_{padding}", compact=True,
                       key_types=(f"TYPE_DES {key_type}",))
    for bits in (1024, 2048):
        keys = (f"TYPE_RSA_PUBLIC LENGTH_RSA_{bits}",
                f"TYPE_RSA_PRIVATE LENGTH_RSA_{bits}",
                f"TYPE_RSA_CRT_PRIVATE LENGTH_RSA_{bits}")
        for alg, pad in (("ALG_RSA_NOPAD", "NOPAD"),
                         ("ALG_RSA_PKCS1", "PKCS1"),
                         ("ALG_RSA_PKCS1_OAEP", "PKCS1_OAEP")):
            cipher(alg, bits, "cc310_if_pinned_driver_supports_it_else_tiny_crypto_c",
                   f"CIPHER_RSA PAD_{pad}", key_types=keys,
                   generation=(f"ALG_RSA LENGTH_RSA_{bits}",
                               f"ALG_RSA_CRT LENGTH_RSA_{bits}"))

    def signature(name, bits, provider, modern, *, compact=False, key_types=(), generation=None):
        rows.append(candidate("signature", name, bits, provider, compact=compact,
                              factories={SIGNATURE: name,
                                         SIGNATURE + ".getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)": modern,
                                         SIGNATURE + ".OneShot.getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)": modern},
                              key_types=key_types, generation=generation))

    for alg, modern in (("ALG_AES_MAC_128_NOPAD", "SIG_CIPHER_AES_MAC128 PAD_NOPAD ALG_NULL"),
                        ("ALG_AES_CMAC_128", "SIG_CIPHER_AES_CMAC128 PAD_NULL ALG_NULL")):
        signature(alg, 128, "cc310", modern, key_types=("TYPE_AES LENGTH_AES_128",))
    for length in (4, 8):
        for padding in ("NOPAD", "ISO9797_M1", "ISO9797_M2", "PKCS5",
                        "ISO9797_1_M1_ALG3", "ISO9797_1_M2_ALG3"):
            alg = f"ALG_DES_MAC{length}_{padding}"
            modern = f"SIG_CIPHER_DES_MAC{length} PAD_{padding} ALG_NULL"
            for bits in (64, 128, 192):
                key_type = {64: "LENGTH_DES", 128: "LENGTH_DES3_2KEY", 192: "LENGTH_DES3_3KEY"}[bits]
                signature(alg, bits, "tiny_crypto_c", modern, compact=True,
                          key_types=(f"TYPE_DES {key_type}",))
    for bits in (256, 384):
        for digest in ("SHA_256", "SHA_384"):
            signature(f"ALG_ECDSA_{digest}", bits,
                      "cc310" if bits == 256 and digest == "SHA_256" else "tiny_crypto_c",
                      f"SIG_CIPHER_ECDSA PAD_NULL ALG_{digest}",
                      key_types=(f"TYPE_EC_FP_PRIVATE LENGTH_EC_FP_{bits}",),
                      generation=f"ALG_EC_FP LENGTH_EC_FP_{bits}")
    for bits in (1024, 2048):
        keys = (f"TYPE_RSA_PUBLIC LENGTH_RSA_{bits}",
                f"TYPE_RSA_PRIVATE LENGTH_RSA_{bits}",
                f"TYPE_RSA_CRT_PRIVATE LENGTH_RSA_{bits}")
        for digest in ("SHA", "SHA_224", "SHA_256", "SHA_384", "SHA_512"):
            for padding, suffix in (("PKCS1", "PKCS1"), ("PKCS1_PSS", "PKCS1_PSS")):
                alg = f"ALG_RSA_{digest}_{suffix}"
                signature(alg, bits, "cc310_if_pinned_driver_supports_it_else_tiny_crypto_c",
                          f"SIG_CIPHER_RSA PAD_{padding} ALG_{digest}",
                          key_types=keys,
                          generation=(f"ALG_RSA LENGTH_RSA_{bits}",
                                      f"ALG_RSA_CRT LENGTH_RSA_{bits}"))

    for digest in ("SHA", "SHA_224", "SHA_256", "SHA_384", "SHA_512"):
        provider = "cc310" if digest in ("SHA", "SHA_224", "SHA_256") else "tiny_crypto_c"
        rows.append(candidate("digest", f"ALG_{digest}", None, provider,
                              factories={section: f"ALG_{digest}" for section in
                                         (DIGEST, DIGEST + ".OneShot", INITIALIZED,
                                          INITIALIZED + ".OneShot")}))
    for bits in (256, 384):
        for name in ("ALG_EC_SVDP_DH_PLAIN", "ALG_EC_SVDP_DH_PLAIN_XY"):
            rows.append(candidate("agreement", name, bits,
                                  "cc310" if bits == 256 else "tiny_crypto_c",
                                  factories={AGREEMENT: name},
                                  key_types=(f"TYPE_EC_FP_PRIVATE LENGTH_EC_FP_{bits}",),
                                  generation=f"ALG_EC_FP LENGTH_EC_FP_{bits}"))
    return rows


def build_profile():
    digest, source = pinned_result()
    rows = []
    for selected in selections():
        probes = {}
        for section, name in selected.pop("factories").items():
            if section not in source or name not in source[section]:
                raise ValueError(f"missing pinned probe: {section}/{name}")
            probes[section] = {"probe": name, "p71d321": "yes" if source[section][name] else "no"}
        key_probes = {}
        for name in selected.pop("key_types"):
            if name not in source[KEY_BUILDER]:
                raise ValueError(f"missing pinned key probe: {name}")
            key_probes[name] = "yes" if source[KEY_BUILDER][name] else "no"
        generation = selected.pop("generation")
        generation_probes = {}
        if generation:
            for name in generation if isinstance(generation, tuple) else (generation,):
                kind = name.split()[0]
                section = f"javacard.security.KeyPair {kind} on-card generation"
                if section not in source or name not in source[section]:
                    raise ValueError(f"missing pinned generation probe: {section}/{name}")
                generation_probes[name] = "yes" if source[section][name] else "no"
        selected["p71d321"] = {"factories": probes, "key_builder": key_probes,
                                "key_pair_generation": generation_probes}
        selected["microcard"] = {
            "advertised": False,
            "key_import": {"status": "pending", "evidence": []} if key_probes else None,
            "key_generation": ({"method": "KeyPair.genKeyPair" if generation_probes else "random_bytes_and_setKey",
                                "status": "pending", "evidence": []} if key_probes else None),
            "operation": {"status": "pending", "evidence": []},
            "invalid_input_and_provider_failure": {"status": "pending", "evidence": []},
            "reboot": {"status": "pending", "evidence": []},
        }
        rows.append(selected)
    return {
        "format": 2,
        "source": "JCAlgTest 1.8.3 P71D321, 2026-06-18",
        "source_sha256": digest,
        "status": "proposed; no operation acceptance inferred from factory scans",
        "admission_rule": "Advertise a factory only after key setup, real operation, invalid-input/provider-failure, and reboot evidence pass on the selected build and DK.",
        "excluded": ["uncommon RSA sizes", "other EC curves", "PACE", "SEED",
                     "ISO9796", "additional random-service aliases"],
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed JSON is stale")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    rendered = json.dumps(build_profile(), indent=2) + "\n"
    if args.check:
        if not args.output.exists() or args.output.read_text() != rendered:
            raise SystemExit(f"stale profile: {args.output}")
    else:
        args.output.write_text(rendered)
    print(f"PASS: {len(json.loads(rendered)['rows'])} selected crypto rows")


if __name__ == "__main__":
    main()
