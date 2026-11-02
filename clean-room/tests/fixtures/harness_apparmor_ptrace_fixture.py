#!/usr/bin/env python3
"""Disposable AppArmor namespace ptrace probe; never a production policy."""

import ctypes
import json
import os
from pathlib import Path
import re
import select
import subprocess
import uuid

PROFILE = Path("/fixture/gateway_ptrace_fixture.apparmor")
NAMESPACES = Path("/sys/kernel/security/apparmor/policy/namespaces")


def read_line(stream):
    if not select.select([stream], [], [], 5)[0]:
        raise RuntimeError("fixture readiness timed out")
    return stream.readline()


def attack(pid, target_fd):
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(reader)
            os.setgroups([])
            os.setgid(2007)
            os.setuid(2007)
            label = Path("/proc/self/attr/current").read_text().strip()
            status = Path("/proc/self/status").read_text()
            effective = next(
                line for line in status.splitlines() if line.startswith("CapEff:")
            )
            if label != "unconfined" or int(effective.split()[1], 16) != 0:
                raise RuntimeError("attacker was not unconfined and unprivileged")
            libc = ctypes.CDLL(None, use_errno=True)
            pidfd = os.pidfd_open(pid)
            duplicate = libc.syscall(438, pidfd, target_fd, 0)
            duplicate_errno = 0 if duplicate >= 0 else ctypes.get_errno()
            if duplicate >= 0:
                os.close(duplicate)
            os.close(pidfd)
            result = libc.ptrace(16, pid, 0, 0)
            trace_errno = 0 if result == 0 else ctypes.get_errno()
            if result == 0:
                os.waitpid(pid, 0)
                if libc.ptrace(17, pid, 0, 0) != 0:
                    os._exit(2)
            os.write(
                writer,
                json.dumps(
                    {"duplicate_errno": duplicate_errno, "trace_errno": trace_errno}
                ).encode(),
            )
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(writer)
    try:
        if not select.select([reader], [], [], 5)[0]:
            raise RuntimeError("attacker timed out")
        data = os.read(reader, 4096)
        _, status = os.waitpid(child, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("attacker failed")
        return json.loads(data)
    finally:
        os.close(reader)


def run_victim(namespace, confined):
    code = """import ctypes,json,os,time
fd=os.open('/dev/null',os.O_RDONLY)
print(json.dumps({'pid':os.getpid(),'fd':fd,'label':open('/proc/self/attr/current').read().strip(),'dumpable':ctypes.CDLL(None).prctl(3,0,0,0,0)}),flush=True)
time.sleep(20)"""
    args = ["/usr/bin/python3.13", "-I", "-B", "-c", code]
    if confined:
        args = [
            "/usr/bin/aa-exec",
            "-p",
            ":" + namespace + "://sfactory-ptrace-fixture",
            "--",
        ] + args
    victim = subprocess.Popen(
        args,
        user=2007,
        group=2007,
        extra_groups=[],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    try:
        line = read_line(victim.stdout)
        if not line:
            raise RuntimeError(
                "victim failed: " + victim.stderr.read().decode(errors="replace")[:500]
            )
        info = json.loads(line)
        if info["pid"] != victim.pid or info["dumpable"] != 1:
            raise RuntimeError("victim identity or exec dumpability changed")
        if confined and (
            "sfactory-ptrace-fixture" not in info["label"]
            or "(enforce)" not in info["label"]
        ):
            raise RuntimeError("candidate profile not enforced")
        if not confined and info["label"] != "unconfined":
            raise RuntimeError("control was unexpectedly confined")
        # Root supervision still needs read-only executable inspection.
        if not os.readlink("/proc/" + str(victim.pid) + "/exe"):
            raise RuntimeError("Root executable inspection failed")
        return attack(victim.pid, info["fd"])
    finally:
        if victim.poll() is None:
            victim.kill()
        victim.wait(timeout=5)
        victim.stdout.close()
        victim.stderr.close()


def main():
    if os.geteuid() != 0 or os.environ.get("SFACTORY_APPARMOR_FIXTURE") != "1":
        raise RuntimeError("explicit disposable Root fixture required")
    if Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() != "0":
        raise RuntimeError("fixture requires the existing ptrace-scope zero control")
    namespace = "sfactory-fixture-" + uuid.uuid4().hex
    if not re.fullmatch(r"sfactory-fixture-[0-9a-f]{32}", namespace):
        raise RuntimeError("fixture namespace invalid")
    owned = NAMESPACES / namespace
    loaded = False
    os.mkdir(owned)
    print(json.dumps({"created_fixture_namespace": namespace}), flush=True)
    try:
        subprocess.run(
            ["/usr/sbin/apparmor_parser", "-n", namespace, "-a", "-T", str(PROFILE)],
            check=True,
            timeout=10,
        )
        loaded = True
        control = run_victim(namespace, False)
        confined = run_victim(namespace, True)
        if control != {"duplicate_errno": 0, "trace_errno": 0}:
            raise RuntimeError(
                "unconfined same-UID positive control was not available: "
                + str(control)
            )
        if confined != {"duplicate_errno": 0, "trace_errno": 0}:
            raise RuntimeError(
                "confined target did not reproduce the observed bypass: "
                + str(confined)
            )
        print(
            json.dumps(
                {
                    "namespace": namespace,
                    "same_uid_ptrace_and_pidfd_control": True,
                    "unconfined_attacker_bypassed_target_policy": True,
                    "root_executable_read": True,
                    "production_admission": False,
                    "paid_calls": 0,
                }
            ),
            flush=True,
        )
    finally:
        if loaded:
            subprocess.run(
                [
                    "/usr/sbin/apparmor_parser",
                    "-n",
                    namespace,
                    "-R",
                    "-T",
                    str(PROFILE),
                ],
                check=True,
                timeout=10,
            )
        os.rmdir(owned)


if __name__ == "__main__":
    main()
