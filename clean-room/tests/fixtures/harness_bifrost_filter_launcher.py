#!/usr/bin/env python3
"""Fixture-only inherited seccomp launch; no production authority."""

import ctypes
import errno
import os
import socket
import sys

sys.path.insert(0, "/code")
from linux_gateway_exec import install_transfer_filter

if len(sys.argv) < 2 or sys.argv[1] not in ("/test.real", "/opt/wallet-gateway-real"):
    raise SystemExit("fixture launch refused")
if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
    raise SystemExit("fixture launch refused")
install_transfer_filter()
left, right = socket.socketpair()
try:
    try:
        left.sendmsg([b"public"])
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        raise SystemExit("fixture filter did not deny sendmsg")
finally:
    left.close()
    right.close()
print("fixture gateway filter verified", flush=True)
os.execve(sys.argv[1], sys.argv[1:], dict(os.environ))
