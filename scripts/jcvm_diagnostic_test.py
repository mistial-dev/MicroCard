import struct
import unittest

from jcvm_diagnostic import WORDS, decode


class DiagnosticWireTest(unittest.TestCase):
    def test_decodes_full_generation_and_separate_apdu_maintenance_counts(self):
        words = list(range(WORDS))
        words[0] = 1
        words[5:7] = [0x12345678, 0x9abcdef0]
        words[49] = 2
        words[50:56] = [0x303, 1, 17, 2, 100, 400000]
        words[56:62] = [0x80000303, 1, 18, 1, 40, 100000]
        words[74] = 0
        data = decode(struct.pack(f">{WORDS}I", *words) + b"\x90\x00")
        self.assertEqual(data["generation"], 0x123456789abcdef0)
        self.assertEqual(data["last_apdu"]["erased_pages"], 23)
        self.assertEqual(data["last_maintenance"]["programmed_words"], 32)
        self.assertEqual(data["last_apdu"]["publication_count"], 2)
        self.assertEqual([entry["erased_pages"] for entry in data["last_apdu"]["publications"]], [2, 1])
        self.assertTrue(data["last_apdu"]["publications"][1]["incomplete"])


if __name__ == "__main__":
    unittest.main()
