"""Root-only creation of a protected bound gateway socket, without launch authority.

The caller must already hold the current Root grant and guard, pass the socket
only to the fenced gateway, close its own descriptor, and reconcile all unknown
outcomes. This module never listens, removes paths, launches or grants spending.
"""

import os
from pathlib import Path
import re
import socket
import stat
import sys

from protected_spending_control import ControlRefused, _ext4, _no_acl

ROOT = Path("/var/lib/sfactory-harness/gw")
NAME = re.compile(r"[0-9a-f]{64}\.sock\Z")


def _require(value, reason):
    if not value:
        raise ControlRefused(reason)


def bind_gateway_socket(attempt_digest, gateway_uid, broker_gid, *, on_created):
    """Bind once; return a non-listening socket and its filesystem identity.

    The parent is preprovisioned by Root. Unknown or failed creation is never
    cleaned up here: a later attempt must not overwrite an ambiguous pathname.
    """
    _require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and isinstance(attempt_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", attempt_digest) is not None
        and type(gateway_uid) is int
        and type(broker_gid) is int
        and 0 < gateway_uid < 2**31
        and 0 < broker_gid < 2**31
        and gateway_uid != broker_gid,
        "gateway_bind_invalid",
    )
    _require(callable(on_created), "gateway_bind_invalid")
    name = attempt_digest + ".sock"
    _require(NAME.fullmatch(name) is not None, "gateway_bind_invalid")
    path = ROOT / name
    _require(len(os.fsencode(path)) < 108, "gateway_bind_path_invalid")
    directories = []
    bound = None
    try:
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        directories.append(descriptor)
        for part in (*ROOT.parts[1:], None):
            info = os.fstat(descriptor)
            _require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022
                and info.st_mode & 0o005 == 0o005,
                "gateway_bind_ancestor_invalid",
            )
            _ext4(descriptor)
            _no_acl(descriptor)
            if part is not None:
                descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                directories.append(descriptor)
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ControlRefused("gateway_bind_already_exists")
        bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        bound.bind(str(path))
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        _require(
            stat.S_ISSOCK(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1,
            "gateway_bind_path_changed",
        )
        identity = {"path": str(path), "dev": before.st_dev, "ino": before.st_ino}
        on_created(identity.copy())
        os.chmod(name, 0o660, dir_fd=descriptor)
        os.chown(
            name, gateway_uid, broker_gid, dir_fd=descriptor, follow_symlinks=False
        )
        after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        _no_acl(path)
        _require(
            (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            and stat.S_ISSOCK(after.st_mode)
            and after.st_nlink == 1
            and after.st_uid == gateway_uid
            and after.st_gid == broker_gid
            and stat.S_IMODE(after.st_mode) == 0o660
            and bound.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and bound.getsockname() == str(path),
            "gateway_bind_path_changed",
        )
        return bound, identity
    except BaseException:
        if bound is not None:
            bound.close()
        raise
    finally:
        for fd in reversed(directories):
            os.close(fd)
