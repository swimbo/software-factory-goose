#!/usr/bin/env python3
"""Network-disabled user-namespace custody experiment; not a launcher."""

import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct

from harness_apparmor_ptrace_fixture import attack, run_victim


UID = 2007


def receive(fd):
    if not select.select([fd], [], [], 5)[0]:
        raise RuntimeError("fixture synchronization timed out")
    return os.read(fd, 4096)


def isolated():
    path = "/fixture-tmp/gateway.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o660)
    os.chown(path, UID, 2008)
    listener.set_inheritable(True)
    ready_r, ready_w = os.pipe()
    gate_r, gate_w = os.pipe()
    out_r, out_w = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_r)
            os.close(gate_w)
            os.close(out_r)
            if ctypes.CDLL(None, use_errno=True).unshare(0x10000000) != 0:
                raise OSError(ctypes.get_errno(), "unshare")
            os.write(ready_w, b"R")
            if os.read(gate_r, 1) != b"G":
                raise RuntimeError("mapping gate closed")
            os.setgroups([])
            os.setgid(UID)
            os.setuid(UID)
            os.dup2(out_w, 1)
            os.execl(
                "/usr/bin/python3.13",
                "/usr/bin/python3.13",
                "-I",
                "-B",
                "-c",
                "import ctypes,json,os,socket,time; "
                f"fd={listener.fileno()}; listener=socket.socket(fileno=fd); listener.listen(1); "
                f"st=os.stat({path!r}); "
                "print(json.dumps({'pid':os.getpid(),'fd':fd,'uid':os.getuid(),"
                "'socket_uid':st.st_uid,'socket_gid':st.st_gid,"
                "'dumpable':ctypes.CDLL(None).prctl(3,0,0,0,0)}),flush=True); time.sleep(20)",
            )
        except BaseException:
            os._exit(1)
    os.close(ready_w)
    os.close(gate_r)
    os.close(out_w)
    listener.close()
    try:
        if receive(ready_r) != b"R":
            raise RuntimeError("namespace child failed")
        proc = Path("/proc") / str(child)
        (proc / "uid_map").write_text("0 0 1\n2007 2007 1\n")
        (proc / "gid_map").write_text("0 0 1\n2007 2007 1\n2008 2008 1\n")
        os.write(gate_w, b"G")
        info = json.loads(receive(out_r))
        if (
            info["pid"] != child
            or info["uid"] != UID
            or info["dumpable"] != 1
            or (info["socket_uid"], info["socket_gid"]) != (UID, 2008)
        ):
            raise RuntimeError("child identity or exec dumpability invalid")
        if os.readlink(proc / "ns/user") == os.readlink("/proc/self/ns/user"):
            raise RuntimeError("child user namespace was not isolated")
        status = (proc / "status").read_text()
        uids = next(line for line in status.splitlines() if line.startswith("Uid:"))
        if uids.split()[1:] != [str(UID)] * 4:
            raise RuntimeError("host-visible UID mismatch")
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        if fields.get("NoNewPrivs", "").strip() != "1" or any(
            int(fields.get(key, "-1").strip(), 16) != 0
            for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        ):
            raise RuntimeError("target retained privilege")
        if not os.readlink(proc / "exe"):
            raise RuntimeError("root executable inspection failed")
        result = attack(child, info["fd"])
        peer_r, peer_w = os.pipe()
        broker = os.fork()
        if broker == 0:
            try:
                os.close(peer_r)
                os.setgroups([])
                os.setgid(2008)
                os.setuid(2008)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(path)
                peer = struct.unpack(
                    "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                os.write(peer_w, json.dumps(peer).encode())
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(peer_w)
        try:
            peer = json.loads(receive(peer_r))
            _, broker_status = os.waitpid(broker, 0)
            if os.waitstatus_to_exitcode(broker_status) != 0 or peer[:2] != [
                child,
                UID,
            ]:
                raise RuntimeError("broker observed unexpected socket peer")
        finally:
            os.close(peer_r)
        return result
    finally:
        for fd in (ready_r, gate_w, out_r):
            os.close(fd)
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child, 0)
        os.unlink(path)


def main():
    if os.geteuid() != 0 or os.environ.get("SFACTORY_USERNS_FIXTURE") != "1":
        raise RuntimeError("explicit disposable Root fixture required")
    if Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() != "0":
        raise RuntimeError("fixture requires existing ptrace-scope zero control")
    control = run_victim("", False)
    restricted = isolated()
    if control != {"duplicate_errno": 0, "trace_errno": 0}:
        raise RuntimeError("same-UID positive control unavailable: " + str(control))
    if restricted != {"duplicate_errno": errno.EPERM, "trace_errno": errno.EPERM}:
        raise RuntimeError("namespace custody failed: " + str(restricted))
    print(
        json.dumps(
            {
                "same_uid_control": control,
                "userns_target": restricted,
                "host_uid_root_exe_and_broker_peer_check": True,
                "production_admission": False,
                "paid_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
