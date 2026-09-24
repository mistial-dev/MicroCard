#!/usr/bin/env python3
"""A transport failure must never be counted as an unsupported algorithm."""
import pathlib
import tempfile

from analyze_jcalgtest_dk import inspect_csv


def main():
    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "result.csv"
        candidate.write_text(
            "Used reader; MicroCard DK\nCard ATR; 3b 80 01 81\n"
            "javacardx.crypto.Cipher\n"
            "ALG_AES;yes;\n"
            "ALG_DES;UNKONWN_ERROR-card_has_return_value_6982;\n"
        )
        metadata, result = inspect_csv(
            candidate,
            {("javacardx.crypto.Cipher", "ALG_AES"): True,
             ("javacardx.crypto.Cipher", "ALG_DES"): False},
        )
        assert metadata["Used reader"] == "MicroCard DK"
        assert result["supported"] == 1
        assert result["missing_probes"] == []
        assert result["error_rows"] == [
            ("javacardx.crypto.Cipher", "ALG_DES",
             "UNKONWN_ERROR-card_has_return_value_6982")]


if __name__ == "__main__":
    main()
