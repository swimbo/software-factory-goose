"""Real Linux pathname limit and held-directory relay binding."""

import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest

from linux_goose_runtime import bind_filesystem_socket


@unittest.skipUnless(sys.platform == "linux", "requires Linux /proc descriptor paths")
class RelayPathTests(unittest.TestCase):
    def test_deep_socket_is_created_in_exact_directory_without_path_shortening(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / ("a" * 70) / ("b" * 70)
            directory.mkdir(parents=True, mode=0o700)
            path = directory / "relay.sock"
            self.assertGreater(len(os.fsencode(path)), 107)
            with socket.socket(socket.AF_UNIX) as server:
                bind_filesystem_socket(server, path)
                self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
                server.listen(1)
                alias = Path(temporary) / "worker-visible.sock"
                os.link(path, alias)
                self.assertEqual(path.lstat().st_ino, alias.lstat().st_ino)
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(alias))
                    connection, _ = server.accept()
                    with connection:
                        client.sendall(b"public")
                        self.assertEqual(connection.recv(6), b"public")
                alias.unlink()
            path.unlink()

    def test_existing_socket_and_symlink_parent_are_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            directory.mkdir(mode=0o700)
            path = directory / "relay.sock"
            with socket.socket(socket.AF_UNIX) as first:
                bind_filesystem_socket(first, path)
                inode = path.lstat().st_ino
                with (
                    socket.socket(socket.AF_UNIX) as second,
                    self.assertRaises(OSError),
                ):
                    bind_filesystem_socket(second, path)
                self.assertEqual(path.lstat().st_ino, inode)
                alias = Path(temporary) / "alias"
                alias.symlink_to(directory, target_is_directory=True)
                with socket.socket(socket.AF_UNIX) as third, self.assertRaises(OSError):
                    bind_filesystem_socket(third, alias / "other.sock")
                self.assertFalse((directory / "other.sock").exists())
            path.unlink()
