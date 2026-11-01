"""Both paired variants must bind the same exact Linux image inputs."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linux_runner import linux_profiles


class LinuxImageBindingTests(unittest.TestCase):
    def test_image_pin_and_recipe_changes_invalidate_both_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "public-binary-placeholder"
            binary.write_bytes(b"profile-hash-only; never executed")
            options = dict(model="auto", route="a" * 64)
            original = linux_profiles(binary, binary, binary, **options)
            read = Path.read_bytes
            for name in ("linux_worker_image.py", "linux-worker.Dockerfile"):

                def changed(path):
                    if path.name == name:
                        return b"different reviewed image input"
                    return read(path)

                with patch.object(Path, "read_bytes", changed):
                    modified = linux_profiles(binary, binary, binary, **options)
                for variant in ("baseline", "candidate"):
                    with self.subTest(name=name, variant=variant):
                        self.assertNotEqual(original[variant], modified[variant])


if __name__ == "__main__":
    unittest.main()
