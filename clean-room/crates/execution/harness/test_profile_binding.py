"""A collector code change must invalidate both frozen harness profiles."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from protected_goose_runtime import profile_fingerprints


class ProfileBinding(unittest.TestCase):
    def test_physical_usage_implementation_is_bound_in_both_profiles(self):
        self.check_source("physical_usage.py")

    def test_gateway_custody_implementation_is_bound_in_both_profiles(self):
        self.check_source("gateway_custody.py")

    def test_physical_settlement_is_bound_in_both_profiles(self):
        self.check_source("physical_settlement.py")

    def check_source(self, name):
        with tempfile.TemporaryDirectory() as directory:
            binaries = [
                Path(directory) / name for name in ("goose", "host", "normalizer")
            ]
            for binary in binaries:
                binary.write_bytes(b"public-binary-fixture")
            before = profile_fingerprints(*binaries, model="auto", route="a" * 64)
            original = Path.read_bytes

            def changed(path):
                value = original(path)
                return (
                    value + b"\n# changed collector\n" if path.name == name else value
                )

            with patch.object(Path, "read_bytes", changed):
                after = profile_fingerprints(*binaries, model="auto", route="a" * 64)
            for variant in ("baseline", "candidate"):
                self.assertNotEqual(before[variant], after[variant])
