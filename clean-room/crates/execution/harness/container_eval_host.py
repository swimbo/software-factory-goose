"""Trusted container PID 1. Receives public inputs only; contains no oracle."""

import base64
import ctypes
import errno
import json
import os
import platform
import resource
import selectors
import stat
import subprocess
import sys
import time


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def deny_fork():
    # Add to Docker's default filter rather than replacing it.
    machine = platform.machine()
    arch, calls = {
        "aarch64": (0xC00000B7, [220, 435]),
        "x86_64": (0xC000003E, [56, 57, 58, 435]),
    }[machine]

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

    rows = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, arch),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
    ]
    if machine == "x86_64":
        rows += [(0x45, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for call in calls:
        rows += [(0x15, 0, 1, call), (0x06, 0, 0, 0x50000 | errno.EPERM)]
    rows += [(0x06, 0, 0, 0x7FFF0000)]
    filters = (Filter * len(rows))(*(Filter(*row) for row in rows))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    program = Program(len(rows), filters)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.addressof(program), 0, 0):
        raise RuntimeError("seccomp")


def child_limits():
    os.setgroups([])
    os.setgid(1001)
    os.setuid(1001)
    for key, value in (
        (resource.RLIMIT_CPU, 5),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_FSIZE, 1048576),
        (resource.RLIMIT_CORE, 0),
    ):
        resource.setrlimit(key, (value, value))
    deny_fork()


def main():
    payload = json.loads(sys.stdin.buffer.read(1572865))
    os.chdir("/work")
    for name, raw in payload["source"].items():
        with open(name, "xb") as stream:
            stream.write(base64.b64decode(raw))
        os.chmod(name, 0o444)
    setup = payload["fixtures"]
    os.chown("scratch", 0, 0)
    for name in setup["directories"]:
        os.makedirs(name, mode=0o700, exist_ok=True)
    for name, raw in setup["files"].items():
        os.makedirs(os.path.dirname(name), mode=0o700, exist_ok=True)
        with open(name, "xb") as stream:
            stream.write(base64.b64decode(raw))
        os.chown(name, 1001, 1001)
    for name, target in setup["symlinks"].items():
        os.symlink(target, name)
    pins = {
        name: os.open(name, os.O_RDONLY | os.O_NOFOLLOW) for name in setup["pin_files"]
    }
    for directory, dirs, names in os.walk("scratch", topdown=False):
        os.chown(directory, 1001, 1001)
    process = subprocess.Popen(
        ["/usr/local/bin/python3", "-I", "-B", "/work/solution.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        preexec_fn=child_limits,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent"},
    )
    pending = memoryview(
        (
            "".join(
                json.dumps(r, separators=(",", ":")) + "\n" for r in payload["requests"]
            )
        ).encode()
    )
    selector = selectors.DefaultSelector()
    for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    os.set_blocking(process.stdin.fileno(), False)
    if pending:
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    else:
        process.stdin.close()
    result = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = timed_out = False
    deadline = time.monotonic() + 6
    while selector.get_map():
        if time.monotonic() >= deadline:
            timed_out = True
            break
        for key, _ in selector.select(0.05):
            if key.data == "stdin":
                try:
                    pending = pending[os.write(key.fd, pending[:4096]) :]
                except BrokenPipeError:
                    pending = memoryview(b"")
                if not pending:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
            else:
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    result[key.data].extend(chunk)
                    if sum(map(len, result.values())) > 65536:
                        overflow = True
        if overflow:
            break
    if not overflow and not timed_out:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)
    files, links = {}, {}
    total = sum(map(len, result.values()))
    os.chown("scratch", 0, 0)
    os.chmod("scratch", 0o700)
    for directory, dirs, names in os.walk("scratch", followlinks=False):
        for leaf in dirs:
            child = directory + "/" + leaf
            if not os.path.islink(child):
                os.chown(child, 0, 0)
                os.chmod(child, 0o700)
        for leaf in dirs + names:
            name = directory + "/" + leaf
            info = os.lstat(name)
            if stat.S_ISLNK(info.st_mode):
                links[name] = os.readlink(name)
            elif stat.S_ISREG(info.st_mode):
                if (
                    info.st_nlink != 1
                    or info.st_size > 65536
                    or total + info.st_size > 524288
                ):
                    overflow = True
                    continue
                os.chown(name, 0, 0)
                os.chmod(name, 0o600)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    raw = os.read(fd, 65537)
                finally:
                    os.close(fd)
                total += len(raw)
                files[name] = encode(raw)
            elif not stat.S_ISDIR(info.st_mode):
                overflow = True
    pinned = {}
    for name, fd in pins.items():
        raw = os.pread(fd, 65537, 0)
        total += len(raw)
        if len(raw) > 65536 or total > 524288:
            overflow = True
        else:
            pinned[name] = encode(raw)
        os.close(fd)
    print(
        json.dumps(
            dict(
                exit_code=process.returncode,
                stdout=encode(bytes(result["stdout"][:65536])),
                stderr=encode(bytes(result["stderr"][:65536])),
                overflow=overflow,
                timed_out=timed_out,
                files=files,
                symlinks=links,
                original_fd_bytes=pinned,
            ),
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"helper_failed":true}')
        sys.exit(1)
