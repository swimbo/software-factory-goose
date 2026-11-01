#!/usr/bin/env python3
"""Native watchdog/cleanup component replay against only fresh fixture resources.

Run inside a trusted Root controller with host PID/cgroup view, DAC_OVERRIDE,
read-only Docker CLI/source and Docker Unix socket; workers have no capabilities,
network, provider credentials or evaluator mount. This deliberately supplies a
single public fixture catalog instead of production RootSupervisor initialization.
The actual watchdog, current-lease checks, strict Docker inspection and cleanup
methods run unchanged. Spending revocation uses an explicit synthetic owner;
this fixture does not prove durable wallet acknowledgement. It does not establish production bootstrap/admission.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
import linux_supervisor as product
from linux_runner import recipe
from linux_goose_runtime import LINUX_GOOSE_SHA256
from protected_goose_runtime import sha

IMAGE = product.WORKER_IMAGE


def docker(*args, timeout=12):
    return subprocess.run(
        ["/fixturebin/docker", "--host", "unix:///run/docker.sock", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )


def slice_unit(method, unit):
    """Operate only the fresh fixture slice through Root's local systemd peer."""
    assert unit.startswith("sfactoryharness") and unit.endswith(".slice")
    assert len(unit) == len("sfactoryharness") + 64 + len(".slice")
    assert all(c in "0123456789abcdef" for c in unit[len("sfactoryharness") : -6])
    lib = ctypes.CDLL("libsystemd.so.0")

    class Error(ctypes.Structure):
        _fields_ = [
            ("name", ctypes.c_char_p),
            ("message", ctypes.c_char_p),
            ("need_free", ctypes.c_int),
        ]

    lib.sd_bus_new.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.sd_bus_set_address.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.sd_bus_start.argtypes = [ctypes.c_void_p]
    lib.sd_bus_call_method.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(Error),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p,
    ]
    lib.sd_bus_unref.argtypes = [ctypes.c_void_p]
    lib.sd_bus_error_free.argtypes = [ctypes.POINTER(Error)]
    lib.sd_bus_message_unref.argtypes = [ctypes.c_void_p]
    bus, reply, error = ctypes.c_void_p(), ctypes.c_void_p(), Error()
    try:
        assert lib.sd_bus_new(ctypes.byref(bus)) >= 0
        assert lib.sd_bus_set_address(bus, b"unix:path=/run/systemd/private") >= 0
        assert lib.sd_bus_start(bus) >= 0
        if method == "StartTransientUnit":
            signature = b"ssa(sv)a(sa(sv))"
            values = [
                ctypes.c_char_p(unit.encode()),
                ctypes.c_char_p(b"fail"),
                ctypes.c_int(3),
            ]
            for key, value in (
                (b"MemoryMax", 1073741824),
                (b"TasksMax", 64),
                (b"CPUQuotaPerSecUSec", 1000000),
            ):
                values += [
                    ctypes.c_char_p(key),
                    ctypes.c_char_p(b"t"),
                    ctypes.c_uint64(value),
                ]
            values += [ctypes.c_int(0)]
        else:
            assert method == "StopUnit"
            signature, values = (
                b"ss",
                [ctypes.c_char_p(unit.encode()), ctypes.c_char_p(b"replace")],
            )
        result = lib.sd_bus_call_method(
            bus,
            b"org.freedesktop.systemd1",
            b"/org/freedesktop/systemd1",
            b"org.freedesktop.systemd1.Manager",
            method.encode(),
            ctypes.byref(error),
            ctypes.byref(reply),
            signature,
            *values,
        )
        assert result >= 0, (result, error.name, error.message)
    finally:
        lib.sd_bus_message_unref(reply)
        lib.sd_bus_error_free(ctypes.byref(error))
        lib.sd_bus_unref(bus)


def ticks(pid):
    try:
        return product._ticks(pid)
    except (OSError, ValueError, IndexError):
        return None


class SyntheticOwner:
    """No wallet or money authority is exercised by this cleanup fixture."""

    def revoke(self, scope):
        assert scope == "5" * 64
        return None


class FixtureSupervisor(product.RootSupervisor):
    """Only initialization and explicit daemon fault injection are fixture seams."""

    def __init__(self, configuration, *, cleanup_only=False):
        assert cleanup_only
        self.configuration = Path(configuration)
        self.cfg = json.loads(product.protected(self.configuration, 0o600))
        self.state, self.catalog = (
            Path(self.cfg["state_root"]),
            Path(self.cfg["catalog_root"]),
        )
        self.recipe, self.slots = self.cfg["recipe"], self.cfg["slots"]
        self.guard = threading.Lock()
        self.owner = SyntheticOwner()

    def _docker(self, *args, timeout=8):
        if self.cfg["fault"] == "daemon_unknown" and args[:2] == ("container", "ls"):
            raise subprocess.CalledProcessError(1, ["fixture-daemon-unavailable"])
        return super()._docker(*args, timeout=timeout)


def setup(base, case_name):
    identity = "run_" + uuid.uuid4().hex + uuid.uuid4().hex
    case = base / case_name
    case.mkdir(mode=0o700)
    state, catalog = case / "state", case / "catalog"
    state.mkdir(mode=0o700)
    catalog.mkdir(mode=0o700)
    saved = state / identity
    saved.mkdir(mode=0o700)
    mounts = saved / "mounts"
    mounts.mkdir(mode=0o700)
    program = b"import subprocess,time\nsubprocess.Popen(['/usr/local/bin/python3','-I','-B','-c','import time;time.sleep(60)'])\ntime.sleep(60)\n"
    for name in product.MOUNT_TARGETS:
        product.store(
            mounts / name, program if name == "worker" else b"public-fixture", 0o444
        )
    group = Path("/sys/fs/cgroup") / ("sfactoryharness" + identity[4:] + ".slice")
    slice_unit("StartTransientUnit", group.name)
    deadline = time.monotonic() + 3
    while not group.exists():
        assert time.monotonic() < deadline, "fresh slice did not materialize"
        time.sleep(0.01)
    now = time.time_ns() // 1000000
    expiry = now + (6000 if case_name == "lease_expiry" else 20000)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    launch_recipe = recipe(
        suite_sha256="b" * 64,
        config_sha256="c" * 64,
        profiles={"baseline": "d" * 64, "candidate": "f" * 64},
        script_host_sha256="1" * 64,
        normalizer_sha256="2" * 64,
        broker_uid=2005,
        worker_uid=2001,
    )
    attempt = dict(
        attempt_id=identity,
        task_id="public-fixture",
        suite_sha256="b" * 64,
        config_sha256="c" * 64,
        goose_build=LINUX_GOOSE_SHA256,
        variant="baseline",
        repeat=0,
        profile="d" * 64,
        model="auto",
        route="e" * 64,
        budget=750000,
        daily_cap=5000000,
        mode="rehearsal",
    )
    admission = dict(
        attempt_id=identity, status="allowed", authority_receipt_sha256="3" * 64
    )
    scope = dict(
        task="01K00000000000000000000001",
        attempt=1,
        generation="01K00000000000000000000000",
        worker="fixture",
        lease_sha256="4" * 64,
        issued_at_ms=now,
        expires_at_ms=expiry,
        route={"route_sha256": "e" * 64},
    )
    metadata = group.stat()
    group_binding = dict(
        path=str(group), dev=metadata.st_dev, ino=metadata.st_ino, boot_id=boot
    )
    control = dict(
        status="allowed",
        attempt_id=identity,
        attempt_sha256=sha(attempt),
        scope_sha256="5" * 64,
        policy_sha256="6" * 64,
        owner="fixture",
        route_sha256="e" * 64,
        expires_at_ms=expiry,
        authority_receipt_sha256="3" * 64,
    )
    entry = dict(
        schema=1,
        attempt=attempt,
        admission_sha256=sha(admission),
        recipe_sha256=sha(launch_recipe),
        scope=scope,
        scope_sha256="5" * 64,
        factory_task_id=scope["task"],
        control_grant=control,
        cgroup=group_binding,
    )
    lease = dict(
        schema=1,
        attempt_sha256=sha(attempt),
        boot_id=boot,
        **{
            k: scope[k]
            for k in (
                "task",
                "generation",
                "worker",
                "lease_sha256",
                "issued_at_ms",
                "expires_at_ms",
            )
        },
    )
    grant = dict(
        schema=1,
        attempt_id=identity,
        attempt_sha256=sha(attempt),
        admission_sha256=sha(admission),
        recipe_sha256=sha(launch_recipe),
        grant_id=uuid.uuid4().hex + uuid.uuid4().hex,
        issued_at_ms=now,
        expires_at_ms=expiry,
        worker_uid=2001,
        broker_uid=2005,
        boot_id=boot,
        cgroup_dev=metadata.st_dev,
        cgroup_ino=metadata.st_ino,
        cgroup_path=str(group),
        workspace_path=str(case / "work"),
        relay_path=str(case / "relay.sock"),
    )
    product.store(catalog / (identity + ".json"), entry)
    product.store(catalog / (identity + ".lease.json"), lease)
    product.store(saved / "grant.json", grant)
    product.store(
        saved / "owner-scope.json",
        {
            "grant_sha256": sha(grant),
            "scope_sha256": "5" * 64,
        },
    )
    product.store(
        saved / "prepare-intent.json", dict(attempt=attempt, admission=admission)
    )
    product.store(saved / "start-intent.json", {"fixture": True})
    config = dict(
        state_root=str(state),
        catalog_root=str(catalog),
        recipe=launch_recipe,
        slots={
            identity: dict(
                attempt_sha256=sha(attempt),
                task_id=attempt["task_id"],
                repeat=0,
                variant="baseline",
                factory_task_id=scope["task"],
            )
        },
        docker="/fixturebin/docker",
        empty_docker_config=str(case / "empty"),
        fault="daemon_unknown" if case_name == "daemon_unknown" else "none",
    )
    (case / "empty").mkdir(mode=0o700)
    configuration = case / "configuration.json"
    product.store(configuration, config)
    return configuration, grant, saved, mounts, group


def run_case(base, name):
    configuration, grant, saved, mounts, group = setup(base, name)
    container = "sfactory-harness-" + grant["attempt_id"][4:]
    owner = watcher = None
    tracked = {}
    try:
        if name == "destructive_guards":
            from unittest.mock import patch

            backend = FixtureSupervisor(configuration, cleanup_only=True)
            outcomes = []
            for field, value in (
                ("boot_id", "00000000-0000-0000-0000-000000000000"),
                ("cgroup_ino", grant["cgroup_ino"] + 1),
                ("cgroup_dev", grant["cgroup_dev"] + 1),
            ):
                changed = dict(grant, **{field: value})
                (saved / "grant.json").unlink()
                product.store(saved / "grant.json", changed)
                try:
                    backend._fence_execution(changed)
                except Exception:
                    refused = True
                else:
                    refused = False
                outcomes.append(
                    {
                        "field": field,
                        "refused": refused,
                        "no_control_write": (group / "cgroup.freeze")
                        .read_text()
                        .strip()
                        == "0",
                        "no_receipt": not (saved / "execution-fenced.json").exists(),
                    }
                )
            (saved / "grant.json").unlink()
            product.store(saved / "grant.json", grant)
            actual_open = os.open
            for control in ("cgroup.freeze", "cgroup.kill"):

                def denied(path, flags, *args, **kwargs):
                    if path == control and flags & os.O_WRONLY:
                        raise OSError("fixture control-write failure")
                    return actual_open(path, flags, *args, **kwargs)

                with patch.object(product.os, "open", side_effect=denied):
                    try:
                        backend._fence_execution(grant)
                    except OSError:
                        refused = True
                    else:
                        refused = False
                outcomes.append(
                    {
                        "control": control,
                        "refused": refused,
                        "no_receipt": not (saved / "execution-fenced.json").exists(),
                    }
                )
            return {
                "case": name,
                "outcomes": outcomes,
                "passed": all(
                    x["refused"] and x["no_receipt"] and x.get("no_control_write", True)
                    for x in outcomes
                ),
            }
        if name == "unknown_create_absence":
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(5)
            connection.connect("/run/docker.sock")
            body = json.dumps({"Image": IMAGE}).encode()
            header = (
                "POST /containers/create?name=" + container + " HTTP/1.1\r\n"
                "Host: localhost\r\nContent-Type: application/json\r\n"
                "Content-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n"
            )
            connection.sendall(header.encode() + body[: len(body) // 2])
            connection.close()  # Lost transport before the complete create body.
            backend = FixtureSupervisor(configuration, cleanup_only=True)
            reason = None
            try:
                backend._cleanup(grant)
            except product.SupervisorRefused as error:
                reason = str(error)
            result = dict(
                case=name,
                create_request_body_incomplete=True,
                cleanup_refusal=reason,
                cleanup_receipt=(saved / "cleanup.json").exists(),
                execution_fence_receipt=(saved / "execution-fenced.json").exists(),
                cgroup_empty="populated 0"
                in (group / "cgroup.events").read_text().splitlines(),
                cgroup_frozen=(group / "cgroup.freeze").read_text().strip() == "1",
                staged_sources_retained=mounts.exists(),
            )
            result["passed"] = (
                reason == "root_create_requires_reconciliation"
                and not result["cleanup_receipt"]
                and result["execution_fence_receipt"]
                and result["cgroup_empty"]
                and result["cgroup_frozen"]
                and result["staged_sources_retained"]
            )
            return result
        args = [
            "create",
            "--pull=never",
            "--name",
            container,
            "--label",
            "sfactory.harness.grant=" + sha(grant),
            "--label",
            "sfactory.harness.attempt=" + grant["attempt_id"],
            "--network",
            "none",
            "--ipc",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "2001:2001",
            "--userns",
            "host",
            "--pids-limit",
            "64",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--cpus",
            "1",
            "--cgroup-parent",
            group.name,
            "--tmpfs",
            "/work:rw,nosuid,nodev,noexec,size=8m,uid=2001,gid=2001,mode=0700",
            "--entrypoint",
            "/usr/local/bin/python3",
        ]
        for key, target in product.MOUNT_TARGETS.items():
            args += [
                "--mount",
                "type=bind,src=" + str(mounts / key) + ",dst=" + target + ",readonly",
            ]
        args += [IMAGE, "-I", "-B", "/factory/linux_worker.py"]
        identity = docker(*args).stdout.strip()
        product.store(saved / "container.json", {"id": identity})
        backend = FixtureSupervisor(configuration, cleanup_only=True)
        if name == "late_queued_start":
            backend._kernel_scope(grant, empty=True)
            backend._fence_execution(grant)
            pending = subprocess.Popen(
                [
                    "/fixturebin/docker",
                    "--host",
                    "unix:///run/docker.sock",
                    "start",
                    identity,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 4
                arrival = False
                while time.monotonic() < deadline:
                    events = (group / "cgroup.events").read_text().splitlines()
                    arrival = "populated 1" in events
                    if arrival:
                        break
                    time.sleep(0.02)
                frozen = (
                    group / "cgroup.freeze"
                ).read_text().strip() == "1" and "frozen 1" in (
                    group / "cgroup.events"
                ).read_text().splitlines()
                backend.revoke({"grant": grant})
                result = dict(
                    case=name,
                    late_arrival_observed=arrival,
                    late_arrival_frozen=frozen,
                    start_requests=1,
                    cleanup_receipt=(saved / "cleanup.json").exists(),
                    execution_fence_receipt=(saved / "execution-fenced.json").exists(),
                    cgroup_empty="populated 0"
                    in (group / "cgroup.events").read_text().splitlines(),
                    cgroup_frozen=(group / "cgroup.freeze").read_text().strip() == "1",
                    staged_sources_retained=mounts.exists(),
                )
                result["passed"] = (
                    arrival
                    and frozen
                    and result["cleanup_receipt"]
                    and result["cgroup_empty"]
                )
                return result
            finally:
                try:
                    pending.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    pending.kill()
                    pending.communicate(timeout=2)
        if name == "unknown_start_ack":
            # Deliver a real start request, never read its acknowledgement and do
            # not retry. A separate read-only observation confirms the fault case.
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(5)
            connection.connect("/run/docker.sock")
            connection.sendall(
                (
                    "POST /containers/" + identity + "/start HTTP/1.1\r\n"
                    "Host: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            try:
                deadline = time.monotonic() + 4
                while True:
                    item = json.loads(docker("inspect", identity).stdout)[0]
                    if item["State"]["Running"]:
                        break
                    assert time.monotonic() < deadline, "lost-ack start did not run"
                    time.sleep(0.02)
            finally:
                connection.close()
        else:
            docker("start", identity)
        parent_limits_before = {
            key: (group / key).read_text().strip()
            for key in ("memory.max", "pids.max", "cpu.max")
        }
        backend = FixtureSupervisor(configuration, cleanup_only=True)
        item = backend._inspect(grant)
        backend._kernel_scope(grant, empty=False)
        parent = item["State"]["Pid"]
        tracked[parent] = ticks(parent)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            children = (
                Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
            )
            if children:
                tracked.update({int(pid): ticks(int(pid)) for pid in children})
                break
            time.sleep(0.02)
        assert len(tracked) >= 2, "worker descendant was not observed"
        if name == "resource_drift":
            (group / "memory.max").write_text("max")
        owner = os.fork()
        if owner == 0:
            time.sleep(30)
            os._exit(0)
        owner_ticks = ticks(owner)
        watcher = os.fork()
        if watcher == 0:
            try:
                product.RootSupervisor = FixtureSupervisor
                product.watchdog(configuration, grant["attempt_id"], owner, owner_ticks)
                os._exit(0)
            except BaseException as error:
                product.store(
                    saved / "watchdog-error.json",
                    {"type": type(error).__name__, "reason": str(error)},
                )
                os._exit(2)
        if name != "lease_expiry":
            os.kill(owner, signal.SIGKILL)
            if name != "zombie_owner":
                os.waitpid(owner, 0)
                owner = None
        deadline = time.monotonic() + (9 if name == "lease_expiry" else 5)
        while time.monotonic() < deadline:
            if (saved / "cleanup.json").exists() and not mounts.exists():
                break
            gone = all(ticks(pid) != value for pid, value in tracked.items())
            if gone and name in ("daemon_unknown", "resource_drift"):
                break
            time.sleep(0.05)
        processes_gone = all(ticks(pid) != value for pid, value in tracked.items())
        empty = (
            group.exists()
            and "populated 0" in (group / "cgroup.events").read_text().splitlines()
        )
        receipt = (saved / "cleanup.json").exists()
        result = dict(
            case=name,
            parent_limits_before_start=parent_limits_before,
            fixture_parent_preprovisioned_by_systemd=True,
            processes_gone=processes_gone,
            cgroup_empty=empty,
            cleanup_receipt=receipt,
            start_acknowledgement_discarded=name == "unknown_start_ack",
            source_start_path_qualified=False,
            discarded_ack_cleanup_component=name == "unknown_start_ack",
            start_requests=1,
            execution_fence_receipt=(saved / "execution-fenced.json").exists(),
            cgroup_frozen=(group / "cgroup.freeze").read_text().strip() == "1"
            if group.exists()
            else False,
            watchdog_error=(
                json.loads((saved / "watchdog-error.json").read_text())
                if (saved / "watchdog-error.json").exists()
                else None
            ),
            remaining_limits=(
                {
                    key: (group / key).read_text().strip()
                    for key in ("memory.max", "pids.max", "cpu.max")
                }
                if group.exists()
                else None
            ),
            staged_sources_retained=mounts.exists(),
        )
        result["passed"] = (
            processes_gone
            and empty
            and result["execution_fence_receipt"]
            and result["cgroup_frozen"]
            and (
                result["staged_sources_retained"] == (not receipt)
                if name == "resource_drift"
                else not receipt and result["staged_sources_retained"]
                if name == "daemon_unknown"
                else receipt and not result["staged_sources_retained"]
            )
        )
        return result
    finally:
        if watcher:
            try:
                finished, _ = os.waitpid(watcher, os.WNOHANG)
                if not finished:
                    os.kill(watcher, signal.SIGKILL)
                    os.waitpid(watcher, 0)
            except ChildProcessError:
                pass
        if owner:
            try:
                os.kill(owner, signal.SIGKILL)
                os.waitpid(owner, 0)
            except ProcessLookupError:
                pass
        subprocess.run(
            [
                "/fixturebin/docker",
                "--host",
                "unix:///run/docker.sock",
                "rm",
                "-f",
                container,
            ],
            capture_output=True,
            timeout=12,
        )
        slice_unit("StopUnit", group.name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument(
        "--cases",
        nargs="+",
        default=[
            "owner_loss",
            "lease_expiry",
            "zombie_owner",
            "daemon_unknown",
            "unknown_start_ack",
            "late_queued_start",
            "unknown_create_absence",
            "resource_drift",
            "destructive_guards",
        ],
    )
    args = parser.parse_args()
    assert os.geteuid() == 0 and not list(args.base.iterdir())
    os.chown(args.base, 0, 0)
    args.base.chmod(0o700)
    outcomes = []
    for name in args.cases:
        assert name in {
            "owner_loss",
            "lease_expiry",
            "zombie_owner",
            "daemon_unknown",
            "unknown_start_ack",
            "late_queued_start",
            "unknown_create_absence",
            "resource_drift",
            "destructive_guards",
        }
        outcomes.append(run_case(args.base, name))
    result = dict(
        schema=1,
        component_only=True,
        product_source_sha256=hashlib.sha256(
            Path(product.__file__).read_bytes()
        ).hexdigest(),
        fixture_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        production_admission=False,
        constructor_replaced_by_public_fixture_initializer=True,
        paid_calls=0,
        live_attempts=0,
        candidate_enabled=False,
        cases=outcomes,
        passed=all(x["passed"] for x in outcomes),
    )
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
