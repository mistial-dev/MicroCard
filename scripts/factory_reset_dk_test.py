import hashlib
import json
import pathlib
import tempfile
import unittest

from factory_reset_dk import ROOT, checked_bundle, checked_debug_image, commands


class FactoryResetTest(unittest.TestCase):
    def test_verified_bundle_and_destructive_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            bundle = base / "bundle"
            bundle.mkdir()
            firmware = bundle / "microcard.elf"
            firmware.write_bytes(b"test image")
            key = base / "management.key"
            key.write_bytes(bytes(range(32)))
            for engine, name, expected_address in (
                ("jcvm", "memory-dk-jcvm.x", 0xF8000),
                ("mc04", "memory-dk.x", 0xE0000),
            ):
                layout = ROOT / "board/nrf52840" / name
                manifest = {
                    "engine": engine,
                    "layout": layout.name,
                    "layout_sha256": hashlib.sha256(layout.read_bytes()).hexdigest(),
                    "sha256": {"microcard.elf": hashlib.sha256(firmware.read_bytes()).hexdigest()},
                    "board_features": ["engine-jcvm", "usb-ccid"] if engine == "jcvm" else ["engine-mc04"],
                }
                if engine == "jcvm":
                    (bundle / "manifest.json").write_text(json.dumps({**manifest, "board_features": ["engine-jcvm"]}))
                    with self.assertRaisesRegex(ValueError, "usb-ccid"):
                        checked_bundle(bundle, key)
                (bundle / "manifest.json").write_text(json.dumps(manifest))
                selected, address = checked_bundle(bundle, key)
                self.assertEqual((selected, address), (firmware, expected_address))
                steps = commands("probe", selected, key, address)
                self.assertEqual([step[1] for step in steps],
                                 ["erase", "download", "download", "reset"])
                self.assertIn("--allow-erase-all", steps[0])
                self.assertEqual(steps[1][-1], str(key))
                self.assertEqual(steps[2][-1], str(firmware))
                if engine == "jcvm":
                    with self.assertRaisesRegex(ValueError, "development-only"):
                        checked_debug_image(bundle)
                    debug_image = bundle / "uicr-debug-open.bin"
                    debug_image.write_bytes(bytes((0x5A, 0, 0, 0)))
                    manifest["development_only"] = True
                    manifest["sha256"][debug_image.name] = hashlib.sha256(
                        debug_image.read_bytes()).hexdigest()
                    (bundle / "manifest.json").write_text(json.dumps(manifest))
                    self.assertEqual(checked_debug_image(bundle), debug_image)
                    debug_steps = commands("probe", selected, key, address, debug_image)
                    self.assertEqual([step[1] for step in debug_steps],
                                     ["erase", "download", "download", "download", "reset"])
                    self.assertIn("0x10001208", debug_steps[3])
                    debug_image.write_bytes(bytes(4))
                    with self.assertRaisesRegex(ValueError, "unverified"):
                        checked_debug_image(bundle)
            firmware.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "firmware does not match"):
                checked_bundle(bundle, key)


if __name__ == "__main__":
    unittest.main()
