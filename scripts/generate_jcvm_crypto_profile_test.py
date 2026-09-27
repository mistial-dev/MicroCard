#!/usr/bin/env python3
"""Check the proposed matrix against the pinned upstream probe names."""

from collections import Counter

from generate_jcvm_crypto_profile import build_profile


def main():
    profile = build_profile()
    rows = profile["rows"]
    assert len(rows) == 110
    assert len({(r["kind"], r["algorithm"], r["key_bits"]) for r in rows}) == len(rows)
    assert Counter(r["kind"] for r in rows) == {
        "cipher": 39, "signature": 62, "digest": 5, "agreement": 4,
    }
    for row in rows:
        assert not row["microcard"]["advertised"]
        assert row["microcard"]["operation"]["status"] == "pending"
        assert row["microcard"]["invalid_input_and_provider_failure"]["status"] == "pending"
        assert row["microcard"]["reboot"]["status"] == "pending"
        assert row["p71d321"]["factories"]
        assert all(p["p71d321"] in {"yes", "no"} for p in row["p71d321"]["factories"].values())
        if row["compact_build"] == "excluded":
            assert row["algorithm"].startswith("ALG_DES_")
            assert row["provider_candidate"] == "tiny_crypto_c"
    assert {r["key_bits"] for r in rows if r["kind"] == "cipher" and r["algorithm"].startswith("ALG_RSA_")} == {1024, 2048}
    assert {r["key_bits"] for r in rows if r["kind"] == "agreement"} == {256, 384}
    assert {r["algorithm"] for r in rows if r["kind"] == "digest"} == {
        "ALG_SHA", "ALG_SHA_224", "ALG_SHA_256", "ALG_SHA_384", "ALG_SHA_512",
    }
    mac4 = [r for r in rows if r["algorithm"] == "ALG_DES_MAC4_NOPAD"]
    assert len(mac4) == 3
    for row in mac4:
        assert row["p71d321"]["factories"]["javacard.crypto.Signature"]["p71d321"] == "no"
        assert row["p71d321"]["factories"]["javacard.crypto.Signature.OneShot.getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)"]["p71d321"] == "yes"
    print("PASS: proposed profile is pinned, bounded, and makes no unverified support claim")


if __name__ == "__main__":
    main()
