#!/usr/bin/env python3
"""Disposable actual PID1 guard/group-loss replay; no provider or production authority.

Run in the bounded Root controller documented by its verification receipt. The
fresh Root-owned namespace is shared with host PID1; sources and configuration
are public fixture inputs. Registry approval and wallet replies are synthetic.
The actual Root constructor, prepare/start, guard service and kernel cleanup run.
"""

import argparse
import contextlib
import ctypes
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import sys
import time

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import linux_supervisor as product
import linux_service_guard as guard
import harness_supervisor_loss_replay as prior

MARKER = "SFACTORY_PID1_GUARD_DISPOSABLE"
OWNER_UID = 700004


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for raw in iter(lambda: source.read(65536), b""):
            h.update(raw)
    return h.hexdigest()


def snapshot(library, unit):
    with guard.SystemdManager(library, digest(library)) as manager:
        return manager.snapshot(unit)


def kill_service_group(library, identity):
    assert identity["ActiveState"] == "active" and identity["MainPID"] > 1
    process = Path("/sys/fs/cgroup") / identity["ControlGroup"].lstrip("/")
    descriptor = os.open(process, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        assert snapshot(library, identity["Id"]) == identity
        control = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            assert os.write(control, b"1") == 1
        finally:
            os.close(control)
    finally:
        os.close(descriptor)


def kill_service_main(library, identity):
    # Use PID1's main-process operation rather than widening the controller's
    # Docker signal policy or killing the cgroup's newly spawned stop-post job.
    with guard.SystemdManager(library, digest(library)) as manager:
        assert manager.snapshot(identity["Id"]) == identity
        message, reply, error = ctypes.c_void_p(), ctypes.c_void_p(), guard._Error()
        try:
            manager._ok(
                manager.lib.sd_bus_message_new_method_call(
                    manager.bus,
                    ctypes.byref(message),
                    manager.DEST,
                    manager.PATH,
                    manager.MANAGER,
                    b"KillUnit",
                )
            )
            manager._basic(message, "s", identity["Id"])
            manager._basic(message, "s", "main")
            number = ctypes.c_int(signal.SIGKILL)
            manager._ok(
                manager.lib.sd_bus_message_append_basic(
                    message, b"i", ctypes.byref(number)
                )
            )
            manager._ok(
                manager.lib.sd_bus_call(
                    manager.bus,
                    message,
                    manager._remaining(),
                    ctypes.byref(error),
                    ctypes.byref(reply),
                )
            )
        finally:
            manager.lib.sd_bus_error_free(ctypes.byref(error))
            manager.lib.sd_bus_message_unref(reply)
            manager.lib.sd_bus_message_unref(message)


def start_gateway_peer(library, python, group, base):
    """Start one fixture-only sibling and child in the existing attempt slice."""
    unit = (
        "sfactoryguard"
        + hashlib.sha256((str(base) + "/gateway-peer").encode()).hexdigest()
        + ".service"
    )
    code = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)']);time.sleep(90)"
    argv = [python, "-I", "-B", "-c", code]
    props = guard.service_policy(argv, [python, "-c", "pass"], 60000000)
    props = [
        (
            key,
            kind,
            group.name
            if key == "Slice"
            else ("nobody" if key == "User" else "nogroup")
            if key in ("User", "Group")
            else value,
        )
        for key, kind, value in props
        if key != "ExecStopPost"
    ]
    with guard.SystemdManager(library, digest(library)) as manager:

        def build(message):
            manager._basic(message, "s", unit)
            manager._basic(message, "s", "fail")
            manager._properties(message, props)
            manager._open(message, "a", "(sa(sv))")
            manager._end(message)

        manager._call("StartTransientUnit", build)
    deadline = time.monotonic() + 4
    while True:
        try:
            identity = snapshot(library, unit)
            pid = identity["MainPID"]
            children = (
                (Path("/proc") / str(pid) / "task" / str(pid) / "children")
                .read_text()
                .split()
            )
            if identity["ActiveState"] == "active" and pid > 1 and len(children) == 1:
                child = int(children[0])
                break
        except (OSError, guard.GuardRefused):
            pass
        assert time.monotonic() < deadline, "gateway peer readiness unknown"
        time.sleep(0.02)
    assert identity["ControlGroup"].startswith("/" + group.name + "/")
    for process in (pid, child):
        fields = dict(
            line.split(":", 1)
            for line in (Path("/proc") / str(process) / "status")
            .read_text()
            .splitlines()
            if ":" in line
        )
        assert (
            fields["Uid"].split() == ["65534"] * 4
            and fields["NoNewPrivs"].strip() == "1"
        )
        assert guard._process_group(process) == identity["ControlGroup"]
    return identity, [(pid, product._ticks(pid)), (child, product._ticks(child))]


def owner_server(path, notify, allow):
    os.setgroups([])
    os.setgid(OWNER_UID)
    os.setuid(OWNER_UID)

    class Server(http.server.HTTPServer):
        address_family = socket.AF_UNIX

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            peer = struct.unpack(
                "3i",
                self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            )
            assert peer[1] == 0
            assert self.path in ("/spending/admit_attempt", "/spending/revoke")
            length = int(self.headers["Content-Length"])
            assert 0 < length <= 65536
            value = json.loads(self.rfile.read(length))
            if self.path.endswith("/revoke"):
                assert value == "5" * 64
                os.write(notify, b"R")
                assert select.select([allow], [], [], 3)[0], (
                    "fixture acknowledgement not released"
                )
                assert os.read(allow, 1) == b"A"
                result = None
            else:
                assert value["task"] == "01K00000000000000000000001"
                result = "5" * 64
            raw = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    with Server(str(path), Handler) as server:
        os.chmod(path, 0o660)
        os.write(notify, b"S")
        server.serve_forever()


def supervisor_main(configuration):
    # This is the actual constructor and entry points. The catalog/gate/owner
    # below are explicit public fixtures, never production bootstrap authority.
    backend = product.RootSupervisor(configuration)
    entry = json.loads((backend.catalog / "active.json").read_bytes())
    attempt, admission = entry["attempt"], entry["admission"]
    grant = backend.prepare(
        {"attempt": attempt, "admission": admission, "recipe": backend.recipe}
    )
    relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = os.open(
        Path(grant["relay_path"]).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        # Root-only fixture creation; production LinuxWorkerRelay uses the
        # broker-owned directory helper and is separately exercised natively.
        relay.bind(f"/proc/self/fd/{descriptor}/relay.sock")
    finally:
        os.close(descriptor)
    os.chmod(grant["relay_path"], 0o660)
    os.chown(grant["relay_path"], grant["broker_uid"], grant["worker_uid"])
    relay.listen(1)
    worker = backend.start(
        {
            "grant": grant,
            "prompt": "Public no-inference group-loss fixture",
            "declarations_sha256": "7" * 64,
            "worker_protocol": "unix-json-v1",
        }
    )
    product.store(
        backend.state / "supervisor-started.json",
        {
            "grant": grant,
            "worker": worker,
            "pid": os.getpid(),
            "ticks": product._ticks(os.getpid()),
        },
    )
    while True:
        time.sleep(1)


def controller(
    base, host_python, host_library, controller_library, fault, gateway_peer=False
):
    assert os.geteuid() == 0 and base.is_absolute()
    assert str(base).startswith("/var/lib/sfactory-harness/qualification-")
    assert (base / MARKER).read_text() == MARKER + "\n"
    assert not (base / "case").exists()
    import unittest

    result = unittest.TextTestRunner().run(
        unittest.defaultTestLoader.loadTestsFromName("test_linux_relay_path")
    )
    assert result.testsRun == 2 and result.wasSuccessful() and not result.skipped
    # Reuse only the fresh public catalog/slice construction, not its replacement
    # supervisor initializer. Clear its never-executed placeholder state.
    configuration, placeholder, saved, mounts, group = prior.setup(base, "case")
    original = json.loads(configuration.read_bytes())
    catalog, state = Path(original["catalog_root"]), Path(original["state_root"])
    active = json.loads((catalog / (placeholder["attempt_id"] + ".json")).read_bytes())
    attempt = active["attempt"]
    # Bound this privileged fixture independently of the benchmark's 180s limit.
    # The observer must not cancel a valid start merely because shared Docker
    # work made its earlier 12s observation window too short.
    expiry = time.time_ns() // 1000000 + 45000
    active["scope"]["expires_at_ms"] = expiry
    active["control_grant"]["expires_at_ms"] = expiry
    entry_path = catalog / (attempt["attempt_id"] + ".json")
    entry_path.unlink()
    product.store(entry_path, active)
    lease_path = catalog / (attempt["attempt_id"] + ".lease.json")
    lease = json.loads(lease_path.read_bytes())
    lease["expires_at_ms"] = expiry
    lease_path.unlink()
    product.store(lease_path, lease)
    admission = json.loads((saved / "prepare-intent.json").read_bytes())["admission"]
    assert json.loads((saved / "start-intent.json").read_bytes()) == {"fixture": True}
    shutil.rmtree(saved)
    runtime = base / "case/runtime"
    runtime.mkdir(mode=0o710)
    os.chown(runtime, 0, original["recipe"]["broker_uid"])
    slots = []
    for task in range(20):
        for repeat in range(3):
            for variant in ("baseline", "candidate"):
                first = task == repeat == 0 and variant == "baseline"
                identity = (
                    attempt["attempt_id"]
                    if first
                    else "run_"
                    + hashlib.sha256(
                        f"public-{task}-{repeat}-{variant}".encode()
                    ).hexdigest()
                )
                slots.append(
                    {
                        "attempt_id": identity,
                        "attempt_sha256": product.sha(attempt)
                        if first
                        else hashlib.sha256(identity.encode()).hexdigest(),
                        "task_id": "public-fixture"
                        if task == 0
                        else f"public-fixture-{task}",
                        "factory_task_id": active["factory_task_id"]
                        if task == 0
                        else f"{task + 1:026d}",
                        "repeat": repeat,
                        "variant": variant,
                    }
                )
    manifest = {
        "schema": 1,
        "suite_sha256": attempt["suite_sha256"],
        "config_sha256": attempt["config_sha256"],
        "attempts": slots,
    }
    product.store(catalog / "index.json", manifest)
    product.store(catalog / "active.json", {"attempt": attempt, "admission": admission})
    program = base / "idle-worker.py"
    product.store(
        program,
        b"import subprocess,time\nsubprocess.Popen(['/usr/local/bin/python3','-I','-B','-c','import time;time.sleep(90)'])\ntime.sleep(90)\n",
        0o444,
    )
    gate = base / "public-gate.py"
    product.store(
        gate,
        b"import contextlib\ndef admission(): return contextlib.nullcontext()\n",
        0o444,
    )
    product.store(
        catalog / (attempt["attempt_id"] + ".launch.json"),
        {
            "prompt_sha256": hashlib.sha256(
                b"Public no-inference group-loss fixture"
            ).hexdigest(),
            "declarations_sha256": "7" * 64,
            "profile_sha256": attempt["profile"],
            "max_output_tokens": 1,
        },
    )
    owner_root = base / "owner"
    owner_root.mkdir(mode=0o755)
    owner_directory = owner_root / "socket"
    owner_directory.mkdir(mode=0o750)
    os.chown(owner_directory, OWNER_UID, OWNER_UID)
    owner_path = owner_directory / "service.sock"
    notification, notify = os.pipe()
    allow, release = os.pipe()
    owner = os.fork()
    if owner == 0:
        try:
            owner_server(owner_path, notify, allow)
        finally:
            os._exit(0)
    os.close(notify)
    os.close(allow)
    assert select.select([notification], [], [], 3)[0]
    assert os.read(notification, 1) == b"S"
    source = Path(product.__file__).parent
    config = {
        "schema": 2,
        "recipe": original["recipe"],
        "runtime_root": str(runtime),
        "catalog_root": str(catalog),
        "catalog_sha256": product.sha(manifest),
        "state_root": str(state),
        "socket_path": str(base / "supervisor.sock"),
        "goose": "/usr/local/libexec/software-factory-goose/goose-protected-802d1478",
        "worker_program": str(program),
        "worker_program_sha256": digest(program),
        "worker_image": product.WORKER_IMAGE,
        "owner_socket": str(owner_path),
        "owner_service_uid": OWNER_UID,
        "registry_gate": str(gate),
        "registry_gate_sha256": digest(gate),
        "python": host_python,
        "python_sha256": digest(host_python),
        "docker": "/usr/bin/docker",
        "docker_sha256": digest("/usr/bin/docker"),
        "empty_docker_config": original["empty_docker_config"],
        "guard_program": str(source / "linux_service_guard.py"),
        "guard_program_sha256": digest(source / "linux_service_guard.py"),
        "supervisor_program": str(source / "linux_supervisor.py"),
        "supervisor_program_sha256": digest(source / "linux_supervisor.py"),
        "systemd_library": host_library,
        "systemd_library_sha256": digest(host_library),
    }
    configuration.unlink()
    product.store(configuration, config)
    unit = "sfactoryguard" + hashlib.sha256(str(base).encode()).hexdigest() + ".service"
    started = None
    parent = None
    guard_ready = None
    gateway = None
    try:
        with guard.SystemdManager(
            controller_library, digest(controller_library)
        ) as manager:
            manager.start(
                unit,
                [
                    host_python,
                    "-I",
                    "-B",
                    str(Path(__file__).resolve()),
                    "supervisor",
                    str(configuration),
                ],
                [host_python, "-I", "-B", str(Path(__file__).resolve()), "noop"],
                60000000,
            )
        deadline = time.monotonic() + 30
        while started is None:
            assert time.monotonic() < deadline, (
                "actual supervisor start did not complete"
            )
            error = configuration.parent / "service-error.json"
            if error.exists():
                try:
                    failure = json.loads(error.read_bytes())
                except json.JSONDecodeError:
                    failure = None
                assert failure is None, failure
            try:
                started = json.loads((state / "supervisor-started.json").read_bytes())
            except (FileNotFoundError, json.JSONDecodeError):
                # Existence precedes store's completed write/fsync. This is a
                # bounded observer read, never a launch or inference retry.
                time.sleep(0.02)
        grant = started["grant"]
        saved = state / grant["attempt_id"]
        guard_ready = json.loads((saved / "guard-ready.json").read_bytes())
        parent = snapshot(controller_library, unit)
        assert (
            parent["MainPID"] == started["pid"]
            and product._ticks(parent["MainPID"]) == started["ticks"]
        )
        guard_group = Path("/sys/fs/cgroup") / guard_ready["cgroup"].lstrip("/")
        limits = {
            name: (guard_group / name).read_text().strip()
            for name in ("memory.max", "pids.max", "cpu.max")
        }
        assert limits["memory.max"] == "268435456" and limits["pids.max"] == "32"
        quota, period = map(int, limits["cpu.max"].split())
        assert quota == period
        if gateway_peer:
            gateway = start_gateway_peer(controller_library, host_python, group, base)
        if fault == "owner-loss":
            kill_service_group(controller_library, parent)
        elif fault == "guard-crash":
            observed = snapshot(controller_library, guard_ready["unit"])
            assert (
                observed["MainPID"] == guard_ready["pid"]
                and observed["InvocationID"] == guard_ready["invocation_id"]
            )
            assert product._ticks(guard_ready["pid"]) == guard_ready["ticks"]
            kill_service_main(controller_library, observed)
        else:
            assert fault == "lease-expiry"
            # Keep both owner and worker live until the actual current lease
            # expires. No catalog edit or synthetic clock drives the guard.
            assert time.time_ns() // 1000000 < expiry
            assert "populated 1" in (group / "cgroup.events").read_text().splitlines()
        wait_seconds = (
            max(0, (expiry - time.time_ns() // 1000000) / 1000) + 5
            if fault == "lease-expiry"
            else 5
        )
        assert select.select([notification], [], [], wait_seconds)[0], (
            "guard did not request scope revocation"
        )
        assert os.read(notification, 1) == b"R"
        # Hold acknowledgement while inspecting the process that actually cleaned up.
        if fault == "owner-loss":
            assert not product._owner_alive(started["pid"], started["ticks"])
            assert product._owner_alive(guard_ready["pid"], guard_ready["ticks"])
        elif fault == "guard-crash":
            assert not product._owner_alive(guard_ready["pid"], guard_ready["ticks"])
            assert product._owner_alive(started["pid"], started["ticks"])
            observed = snapshot(controller_library, guard_ready["unit"])
            assert observed["InvocationID"] == guard_ready["invocation_id"]
            assert observed["SubState"] == "stop-post"
            assert (guard_group / "cgroup.procs").read_text().strip()
        else:
            assert time.time_ns() // 1000000 >= expiry
            assert product._owner_alive(started["pid"], started["ticks"])
            assert product._owner_alive(guard_ready["pid"], guard_ready["ticks"])
        assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
        assert (group / "cgroup.freeze").read_text().strip() == "1"
        if gateway_peer:
            assert all(
                not product._owner_alive(pid, ticks) for pid, ticks in gateway[1]
            )
            observed_gateway = snapshot(controller_library, gateway[0]["Id"])
            assert observed_gateway["InvocationID"] == gateway[0]["InvocationID"]
            assert (
                observed_gateway["MainPID"] == 0
                and observed_gateway["ActiveState"] != "active"
            )
        os.write(release, b"A")
        deadline = time.monotonic() + 5
        while not (saved / "owner-revoked.json").exists():
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert (saved / "execution-fenced.json").exists() and (
            saved / "cleanup.json"
        ).exists()
        result = {
            "schema": 1,
            "component_only": True,
            "actual_root_constructor_prepare_start": True,
            "actual_pid1_guard": True,
            "native_long_relay_path_tests": 2,
            "fault": fault,
            "entire_supervisor_group_killed": fault == "owner-loss",
            "guard_alive_after_supervisor_group_loss": fault == "owner-loss",
            "guard_exec_stop_post_cleanup": fault == "guard-crash",
            "lease_expired_with_live_supervisor": fault == "lease-expiry",
            "guard_cgroup_limits": limits,
            "exact_worker_fenced_and_removed": True,
            "fixture_gateway_peer_and_child_fenced": gateway_peer,
            "synthetic_owner_revocation_acknowledged": True,
            "synthetic_catalog_registry_owner": True,
            "production_admission": False,
            "paid_calls": 0,
            "live_attempts": 0,
            "candidate_enabled": False,
            "guard_unit": guard_ready["unit"],
            "supervisor_unit": unit,
            "owned_worker_slice": group.name,
            "fixture_gateway_unit": gateway[0]["Id"] if gateway else None,
            "source_sha256": {
                p.name: digest(p)
                for p in (Path(product.__file__), Path(guard.__file__), Path(__file__))
            },
        }
        print(json.dumps(result, sort_keys=True), flush=True)
    finally:
        if (
            parent is not None
            and started is not None
            and product._owner_alive(started["pid"], started["ticks"])
        ):
            kill_service_group(controller_library, parent)
        os.close(release)
        os.close(notification)
        # Unknown queued work retains its frozen cgroup and evidence.
        retained = state / attempt["attempt_id"] / "grant.json"
        if retained.exists():
            retire_worker_slice(configuration, json.loads(retained.read_bytes()), group)
        with contextlib.suppress(ProcessLookupError):
            os.kill(owner, signal.SIGKILL)
        os.waitpid(owner, 0)


def retire_worker_slice(configuration, grant, group):
    try:
        stopped = product.RootSupervisor(configuration, cleanup_only=True).revoke(
            {"grant": grant}
        )
    except Exception:
        return False
    if stopped != {"grant_sha256": product.sha(grant), "state": "stopped"}:
        return False
    prior.slice_unit("StopUnit", group.name)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("controller", "supervisor", "noop"))
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--host-python")
    parser.add_argument("--host-library")
    parser.add_argument("--controller-library")
    parser.add_argument("--gateway-peer", action="store_true")
    parser.add_argument(
        "--fault",
        choices=("owner-loss", "guard-crash", "lease-expiry"),
        default="owner-loss",
    )
    args = parser.parse_args()
    if args.mode == "supervisor":
        try:
            supervisor_main(args.path)
        except Exception as error:
            product.store(
                args.path.parent / "service-error.json",
                {"type": type(error).__name__, "reason": str(error)[:512]},
            )
            raise
    elif args.mode == "controller":
        controller(
            args.path,
            args.host_python,
            args.host_library,
            args.controller_library,
            args.fault,
            args.gateway_peer,
        )


if __name__ == "__main__":
    main()
