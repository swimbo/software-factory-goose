#!/usr/bin/env python3
"""Actual constructor and broker RPC with disposable, synthetic public authority.

Inputs are a fresh Root-owned qualification directory and the separately built
public SQLite fixture generator. No wallet/capture exchange or paid call occurs.
Cleanup controls use only newly created, individually recorded resources.
"""

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import linux_supervisor as product
import harness_supervisor_loss_replay as prior

OWNER_UID = 700004
MARKER = "PUBLIC_ROOT_COLD_GATEWAY_FIXTURE"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for raw in iter(lambda: source.read(65536), b""):
            h.update(raw)
    return h.hexdigest()


def rpc(path, method, body):
    import http.client

    connection = http.client.HTTPConnection("localhost", timeout=25)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.settimeout(25)
    connection.sock.connect(path)
    connection.request("POST", "/harness-launch/" + method, json.dumps(body))
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, raw


def broker(path, prepare, result_path):
    if os.geteuid() == 0:
        os.setgroups([2001])
        os.setgid(2005)
        os.setuid(2005)
    else:
        assert os.geteuid() == 2005
    status, raw = rpc(path, "prepare", prepare)
    assert status == 200, (status, raw)
    grant = json.loads(raw)
    Path(result_path).with_name("prepared.json").write_text(json.dumps(grant))
    relay = socket.socket(socket.AF_UNIX)
    # Use the existing deep-path-safe broker relay helper's held directory form.
    directory = os.open(Path(grant["relay_path"]).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        relay.bind(f"/proc/self/fd/{directory}/relay.sock")
    finally:
        os.close(directory)
    os.chmod(grant["relay_path"], 0o660)
    os.chown(grant["relay_path"], 2005, 2001)
    relay.listen(1)
    status, raw = rpc(
        path,
        "start",
        {
            "grant": grant,
            "prompt": "Public cold gateway start fixture",
            "declarations_sha256": "7" * 64,
            "worker_protocol": "unix-json-v1",
        },
    )
    result = {"status": status, "response": raw.decode(), "grant": grant}
    if status == 200:
        observed_status, observed = rpc(
            path, "observe", {"grant": grant, "worker": json.loads(raw)}
        )
        result.update(
            observed_status=observed_status, observed_response=observed.decode()
        )
    Path(result_path).write_text(json.dumps(result))
    relay.close()


def custody_attacks(base, pid, custody):
    """Public controls target only this fixture's unchanged gateway process."""
    from harness_apparmor_ptrace_fixture import run_victim

    positive = run_victim("", False)
    assert positive == {"duplicate_errno": 0, "trace_errno": 0}, positive
    targets = {}
    for entry in (Path("/proc") / str(pid) / "fd").iterdir():
        link = os.readlink(entry)
        if link == "socket:[" + str(custody["kernel_ino"]) + "]":
            targets["socket"] = int(entry.name)
        if "memfd:sfactory-gateway-bootstrap" in link:
            targets["configuration"] = int(entry.name)
    assert "socket" in targets, targets
    config_closed = "configuration" not in targets
    if config_closed:
        spawn = json.loads((base / "actual-helper-spawn.json").read_bytes())
        targets["configuration"] = json.loads(spawn["argv"][4])["helper_config"][
            "bootstrap_fd"
        ]
    results = []
    # Worker and evaluator-like external roles, plus an outside same-UID attacker.
    for uid in (2001, 2006, 2007):
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(reader)
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
                libc = ctypes.CDLL(None, use_errno=True)
                pidfd = os.pidfd_open(pid)
                values = {}
                try:
                    database = os.open(base / "gateway-state/public.db", os.O_RDONLY)
                except OSError as error:
                    database_access = {"readable": False, "errno": error.errno}
                else:
                    database_access = {
                        "readable": os.read(database, 16) == b"SQLite format 3\0"
                    }
                    os.close(database)
                for name, fd in targets.items():
                    copied = libc.syscall(438, pidfd, fd, 0)
                    values[name] = 0 if copied >= 0 else ctypes.get_errno()
                    if copied >= 0:
                        os.close(copied)
                os.close(pidfd)
                try:
                    namespace = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
                except OSError as error:
                    values["namespace"] = error.errno
                else:
                    changed = libc.setns(namespace, 0x10000000)
                    values["namespace"] = 0 if changed == 0 else ctypes.get_errno()
                    os.close(namespace)
                os.write(
                    writer,
                    json.dumps(
                        {
                            "uid": uid,
                            "errors": values,
                            "public_database": database_access,
                        }
                    ).encode(),
                )
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(writer)
        raw = os.read(reader, 4096)
        os.close(reader)
        _, status = os.waitpid(child, 0)
        assert status == 0
        value = json.loads(raw)
        assert all(
            code in (errno.EPERM, errno.EACCES) for code in value["errors"].values()
        ), value
        assert value["public_database"]["readable"] is (uid == 2007), value
        results.append(value)
    product.store(
        base / "custody-attacks.json",
        {
            "positive": positive,
            "targets": targets,
            "configuration_descriptor_closed": config_closed,
            "denied": results,
        },
    )


def main(base, builder, binary, scenario="positive"):
    joined = None
    if scenario in ("joined-success", "joined-provider-unknown", "joined-capture-unknown", "joined-missing-classifier"):
        from harness_wallet_gateway_join_replay import PublicRootWalletRehearsal
        joined = PublicRootWalletRehearsal(base, scenario.removeprefix("joined-"))
        scenario = "missing-classifier" if joined.mode == "missing-classifier" else "positive"
    assert scenario in (
        "positive",
        "missing-classifier",
        "cleanup-normal",
        "cleanup-guard",
        "cleanup-descendant-guard",
        "cleanup-descendant-normal",
        "cleanup-lease",
        "cleanup-owner",
        "cleanup-missing-inode",
        "cleanup-replaced-inode",
        "cleanup-changed-lineage",
        "cleanup-daemon-outage",
        "cleanup-revoke-unknown",
        "ready-reader-closed",
        "ready-pipe-full",
        "gateway-exits-during-create",
        "gateway-exits-before-observe",
    )
    holding_descendant = scenario in (
        "cleanup-descendant-guard",
        "cleanup-descendant-normal",
    )
    if holding_descendant:
        scenario = "cleanup-guard" if scenario.endswith("-guard") else "cleanup-normal"
    assert os.geteuid() == 0 and str(base).startswith(
        "/var/lib/sfactory-harness/qualification-"
    )
    assert (base / MARKER).read_text() == MARKER + "\n"
    assert not (base / "case").exists()
    calls = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            calls.append(self.path)
            if joined is not None:
                joined.provider(self)
            else:
                self.send_error(500)

    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/systemd/private"
    upstream = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    subprocess.run(
        [
            str(builder),
            "-test.run=^TestPublicRootFixture$",
            "-test.v",
            "-test.timeout=30s",
        ],
        env={
            "PUBLIC_ROOT_BASE": str(base),
            "PUBLIC_ROOT_UPSTREAM": f"http://127.0.0.1:{upstream.server_port}",
            "TMPDIR": str(base),
        },
        check=True,
        timeout=40,
    )
    allowance = json.loads((base / "allowance.json").read_bytes())
    if joined is not None:
        allowance = joined.configure(allowance)
        (base / "allowance.json").write_text(json.dumps(allowance))
    scope_sha = product.factory_scope_digest(allowance)
    configuration, placeholder, saved, _, group = prior.setup(base, "case")
    configuration.parent.chmod(
        0o755
    )  # Public broker traversal; protected leaves stay private.
    original = json.loads(configuration.read_bytes())
    catalog, state = Path(original["catalog_root"]), Path(original["state_root"])
    entry_path = catalog / (placeholder["attempt_id"] + ".json")
    active = json.loads(entry_path.read_bytes())
    attempt = active["attempt"]
    if joined is not None:
        attempt.update(budget_owner=joined.owner, cost_basis="audited_usage_rated",
                       tariff_sha256=joined.card.sha256())
        active["control_grant"].update(cost_basis="audited_usage_rated",
                                         tariff_sha256=joined.card.sha256())
        active["control_grant"]["attempt_sha256"] = product.sha(attempt)
    active["scope"] = allowance
    active["scope_sha256"] = scope_sha
    active["control_grant"]["scope_sha256"] = scope_sha
    active["control_grant"]["owner"] = "public-owner"
    deadline = time.time_ns() // 1000000 + 90000
    active["control_grant"]["expires_at_ms"] = deadline
    entry_path.unlink()
    product.store(entry_path, active)
    lease_path = catalog / (attempt["attempt_id"] + ".lease.json")
    lease = json.loads(lease_path.read_bytes())
    lease.update(
        {
            k: allowance[k]
            for k in ("task", "generation", "worker", "lease_sha256", "issued_at_ms")
        }
    )
    lease["expires_at_ms"] = deadline
    if joined is not None:
        lease["attempt_sha256"] = product.sha(attempt)
    lease_path.unlink()
    product.store(lease_path, lease)
    admission = json.loads((saved / "prepare-intent.json").read_bytes())["admission"]
    shutil.rmtree(saved)  # Only the fresh never-executed placeholder from setup.
    runtime = base / "case/runtime"
    runtime.mkdir(mode=0o710)
    os.chown(runtime, 0, 2005)
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
    product.store(
        catalog / (attempt["attempt_id"] + ".launch.json"),
        {
            "prompt_sha256": hashlib.sha256(
                b"Public cold gateway start fixture"
            ).hexdigest(),
            "declarations_sha256": "7" * 64,
            "profile_sha256": attempt["profile"],
            "max_output_tokens": 16 if joined is not None else 8,
        },
    )
    worker = base / "idle-worker.py"
    product.store(
        worker,
        b"import time\ntime.sleep(3)\n"
        if scenario == "cleanup-normal"
        else b"import time\ntime.sleep(120)\n",
        0o444,
    )
    gate = base / "public-gate.py"
    product.store(
        gate,
        b"import contextlib\ndef admission(): return contextlib.nullcontext()\n",
        0o444,
    )
    # Three separate service UIDs. Broker/capture sockets are public no-call
    # endpoints; the wallet owner only acknowledges synthetic admit/revoke.
    children = []
    if joined is not None:
        joined.start_services()
    for name, uid in (() if joined is not None else (("owner", OWNER_UID), ("broker", 2005), ("capture", 2008))):
        directory = base / name
        directory.mkdir(mode=0o755)
        os.chown(directory, uid, uid)
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            os.setgroups([])
            os.setgid(2007 if name != "owner" else 0)
            os.setuid(uid)

            class Service(http.server.HTTPServer):
                address_family = socket.AF_UNIX

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_POST(self):
                    peer = struct.unpack(
                        "3i",
                        self.connection.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                        ),
                    )
                    assert name == "owner" and peer[1] == 0
                    value = json.loads(
                        self.rfile.read(int(self.headers["Content-Length"]))
                    )
                    if self.path == "/spending/admit_attempt":
                        assert value == allowance
                        result = scope_sha
                    else:
                        assert self.path == "/spending/revoke" and value == scope_sha
                        if scenario == "cleanup-revoke-unknown":
                            self.send_error(
                                503, "public fixture lost revocation acknowledgement"
                            )
                            return
                        result = None
                    raw = json.dumps(result).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

            with Service(str(directory / "socket"), Handler) as service:
                os.chown(directory / "socket", uid, 2007 if name != "owner" else 0)
                os.chmod(directory / "socket", 0o660)
                os.write(writer, b"S")
                os.close(writer)
                service.serve_forever()
            os._exit(0)
        children.append(child)
        os.close(writer)
        assert os.read(reader, 1) == b"S"
        os.close(reader)
    source = Path(product.__file__).parent
    cfg = dict(
        schema=5,
        recipe=original["recipe"],
        runtime_root=str(runtime),
        catalog_root=str(catalog),
        catalog_sha256=product.sha(manifest),
        state_root=str(state),
        socket_path=str(base / "supervisor.sock"),
        goose="/usr/local/libexec/software-factory-goose/goose-protected-802d1478",
        worker_program=str(worker),
        worker_program_sha256=digest(worker),
        worker_image=product.WORKER_IMAGE,
        owner_socket=str(base / "owner/socket"),
        owner_service_uid=2004 if joined is not None else OWNER_UID,
        registry_gate=str(gate),
        registry_gate_sha256=digest(gate),
        python="/usr/bin/python3.13",
        python_sha256=digest("/usr/bin/python3.13"),
        docker="/usr/bin/docker",
        docker_sha256=digest("/usr/bin/docker"),
        empty_docker_config=original["empty_docker_config"],
        guard_program=str(source / "linux_service_guard.py"),
        guard_program_sha256=digest(source / "linux_service_guard.py"),
        supervisor_program=str(source / "linux_supervisor.py"),
        supervisor_program_sha256=digest(source / "linux_supervisor.py"),
        systemd_library="/usr/lib/x86_64-linux-gnu/libsystemd.so.0.40.0",
        systemd_library_sha256=digest("/usr/lib/x86_64-linux-gnu/libsystemd.so.0.40.0"),
        gateway_uid=2007,
        gateway_executable_sha256=digest(binary),
        gateway_socket_sha256=product.GATEWAY_SOCKET_SHA256,
        gateway_program=str(binary),
        gateway_bootstrap_template=str(base / "template.json"),
        gateway_bootstrap_template_sha256=digest(base / "template.json"),
        capture_service_uid=2008,
    )
    configuration.unlink()
    product.store(configuration, cfg)
    result_dir = base / "broker-result"
    result_dir.mkdir(mode=0o700)
    os.chown(result_dir, 2005, 2005)

    def error_record(error):
        queue, seen, records = [error], set(), []
        while queue:
            item = queue.pop()
            if item is None or id(item) in seen:
                continue
            seen.add(id(item))
            records.append({"type": type(item).__name__, "reason": str(item)})
            queue.extend((item.__cause__, item.__context__))
        return {"errors": records}

    class TracedRoot(product.RootSupervisor):
        # Diagnostics only: the inherited real constructor and original public
        # methods keep all checks; no fixture authority bypass is installed.
        def _docker(self, *args):
            self.public_docker_calls = getattr(self, "public_docker_calls", [])
            self.public_docker_calls.append(args[0])
            before_create = (
                scenario == "gateway-exits-during-create" and args[0] == "create"
            )
            after_start = (
                scenario == "gateway-exits-before-observe" and args[0] == "start"
            )
            if before_create:
                self._inject_gateway_loss("before-create")
            result = super()._docker(*args)
            if after_start:
                self._inject_gateway_loss("after-worker-start")
            return result

        def _inject_gateway_loss(self, phase):
            assert len(self.gateway_children) == 1
            process = next(iter(self.gateway_children.values()))
            case = self._case(next(iter(self.gateway_children)))
            frozen = json.loads((case / "gateway-bootstrap.json").read_bytes())
            assert frozen["deadline_ms"] - time.time_ns() // 1000000 >= 10000
            ticks = product._ticks(process.pid)
            assert process.poll() is None
            assert (
                digest(Path(f"/proc/{process.pid}/exe"))
                == cfg["gateway_executable_sha256"]
            )
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            product.store(
                base / "gateway-loss-control.json",
                {
                    "pid": process.pid,
                    "ticks": ticks,
                    "phase": phase,
                    "executable_sha256": cfg["gateway_executable_sha256"],
                    "exit_code": process.returncode,
                },
            )

        def _prepare_gateway(self, grant, bound, program, **kwargs):
            if scenario == "ready-reader-closed":
                writer = kwargs["cold_ready_fd"]
                identity = os.fstat(writer)
                readers = []
                for entry in os.listdir("/proc/self/fd"):
                    fd = int(entry)
                    try:
                        info = os.fstat(fd)
                        if (info.st_dev, info.st_ino) == (
                            identity.st_dev,
                            identity.st_ino,
                        ) and fcntl.fcntl(
                            fd, fcntl.F_GETFL
                        ) & os.O_ACCMODE == os.O_RDONLY:
                            readers.append(fd)
                    except OSError:
                        pass
                assert len(readers) == 1
                reader = readers[0]
                os.close(reader)
                # Reserve the closed reader's number with an owned harmless
                # descriptor, so final Root close cannot race descriptor reuse.
                replacement = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                if replacement != reader:
                    os.dup2(replacement, reader, inheritable=False)
                    os.close(replacement)
                product.store(
                    base / "pipe-control.json",
                    {
                        "scenario": scenario,
                        "pipe_dev": identity.st_dev,
                        "pipe_ino": identity.st_ino,
                        "reader_closed": True,
                    },
                )
            elif scenario == "ready-pipe-full":
                writer = kwargs["cold_ready_fd"]
                size = fcntl.fcntl(writer, fcntl.F_SETPIPE_SZ, 4096)
                assert size == 4096
                os.set_blocking(writer, False)
                assert os.write(writer, b"x" * size) == size
                product.store(
                    base / "pipe-control.json",
                    {"scenario": scenario, "filled_bytes": size},
                )
            return super()._prepare_gateway(grant, bound, program, **kwargs)

        def _accept_gateway_ready(self, grant, process, reader, frozen):
            if scenario in ("ready-reader-closed", "ready-pipe-full"):
                start = time.monotonic()
                observed = None
                while process.poll() is None and time.monotonic() - start < 5:
                    try:
                        if (
                            digest(Path(f"/proc/{process.pid}/exe"))
                            == cfg["gateway_executable_sha256"]
                        ):
                            observed = {
                                "pid": process.pid,
                                "ticks": product._ticks(process.pid),
                                "executable_sha256": cfg["gateway_executable_sha256"],
                            }
                    except OSError:
                        pass
                    time.sleep(0.002)
                assert process.poll() is not None, (
                    "actual command hung on readiness pipe"
                )
                assert observed is not None, "post-exec command identity not observed"
                product.store(
                    base / "actual-command-failure.json",
                    observed
                    | {
                        "scenario": scenario,
                        "exit_code": process.returncode,
                        "wall_seconds": time.monotonic() - start,
                    },
                )
            return super()._accept_gateway_ready(grant, process, reader, frozen)

        def prepare(self, body):
            try:
                return super().prepare(body)
            except Exception as error:
                product.store(
                    base / "prepare-error.json",
                    error_record(error),
                )
                raise

        def start(self, body):
            try:
                return super().start(body)
            except Exception as error:
                product.store(
                    base / "start-error.json",
                    error_record(error)
                    | {
                        "gateway_exit_codes": [
                            p.returncode for p in self.gateway_children.values()
                        ]
                    },
                )
                raise

        def observe(self, body):
            try:
                return super().observe(body)
            except Exception as error:
                product.store(base / "observe-error.json", error_record(error))
                raise

    if scenario == "cleanup-guard":
        import linux_service_guard as service_guard

        original_policy = service_guard.service_policy

        def logged_policy(*args):
            return [
                (
                    "StandardErrorFileToAppend" if name == "StandardError" else name,
                    kind,
                    str(base / "guard-stderr.log")
                    if name == "StandardError"
                    else value,
                )
                for name, kind, value in original_policy(*args)
            ]

        service_guard.service_policy = logged_policy
    if joined is not None:
        joined.start_broker(cfg, {"attempt": attempt, "admission": admission, "recipe": cfg["recipe"]},
                            result_dir / "result.json")
    backend = TracedRoot(configuration)
    original_popen = product.subprocess.Popen
    helper_children = []
    helper_log = os.open(
        base / "helper-stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )

    def traced_popen(args, *positional, **kwargs):
        actual_helper = (
            isinstance(args, list)
            and len(args) >= 4
            and args[0] == cfg["python"]
            and str(args[3]).startswith("/proc/self/fd/")
        )
        if actual_helper:
            kwargs = kwargs | {"stderr": helper_log}
        process = original_popen(args, *positional, **kwargs)
        if actual_helper:
            identity = {"pid": process.pid, "ticks": product._ticks(process.pid)}
            helper_children.append(identity)
            product.store(
                base / "actual-helper-spawn.json",
                identity
                | {
                    "argv": args,
                    "pass_fds": list(kwargs["pass_fds"]),
                    "userns_sha256": product.GATEWAY_USERNS_SHA256,
                    "exec_sha256": product.GATEWAY_EXEC_SHA256,
                },
            )
        return process

    product.subprocess.Popen = traced_popen
    backend_pid = os.getpid()
    grant = None
    try:
        with product.Server(backend) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            child = os.fork() if joined is None else joined.broker_pid
            if joined is not None:
                joined.wrong_broker(cfg, {"attempt": attempt, "admission": admission, "recipe": cfg["recipe"]})
                assert not any(state.iterdir()), "wrong broker created consumed intent"
                (base / "broker-start").touch(mode=0o644)
            if child == 0:
                try:
                    broker(
                        cfg["socket_path"],
                        {
                            "attempt": attempt,
                            "admission": admission,
                            "recipe": cfg["recipe"],
                        },
                        result_dir / "result.json",
                    )
                except BaseException as error:
                    (result_dir / "broker-error.json").write_text(
                        json.dumps({"type": type(error).__name__, "reason": str(error)})
                    )
                    os._exit(1)
                os._exit(0)
            _, broker_status = os.waitpid(child, 0)
            if broker_status:
                for name in (
                    "prepare-error.json",
                    "start-error.json",
                    "broker-result/broker-error.json",
                ):
                    if (base / name).exists():
                        print(name, (base / name).read_text(), flush=True)
                raise RuntimeError("public broker RPC fixture failed")
            result = json.loads((result_dir / "result.json").read_bytes())
            grant = result["grant"]
            product.store(base / "public-start-result.json", result)
            if scenario == "positive" or scenario.startswith("cleanup-"):
                if result["status"] != 200:
                    print(
                        "start-error.json",
                        (base / "start-error.json").read_text(),
                        flush=True,
                    )
                assert result["status"] == 200, result
                case = backend._saved(grant)
                cold = json.loads((case / "gateway-cold-ready.json").read_bytes())
                assert (
                    cold["grant_sha256"]
                    == product.sha(grant)
                    != cold["scope_sha256"]
                    == scope_sha
                )
                assert cold["paid_ready"] is False and cold["pid"] in [
                    p.pid for p in backend.gateway_children.values()
                ]
                assert result["observed_status"] == 200, result
                assert json.loads(result["observed_response"])["state"] == "running"
            elif scenario == "missing-classifier":
                case = backend._saved(grant)
                assert result["status"] == 503 and not (case / "gateway-cold-ready.json").exists()
                assert not (case / "worker.json").exists() and not calls
                with sqlite3.connect(base / "w/capture/state/capture.db") as db:
                    assert db.execute("SELECT count(*) FROM roots").fetchone() == (0,)
                product.store(base / "missing-classifier-proof.json", {
                    "start_status": 503, "provider_http": 0, "acquired_owners": 0,
                    "cold_ready": False, "worker_started": False})
            elif scenario in ("ready-reader-closed", "ready-pipe-full"):
                assert result["status"] == 503, result
                case = backend._saved(grant)
                assert (case / "start-intent.json").exists() and (
                    case / "gateway-release-intent.json"
                ).exists()
                assert (
                    not (case / "gateway-cold-ready.json").exists()
                    and not (case / "worker.json").exists()
                    and not (case / "container.json").exists()
                )
                failure = json.loads(
                    (base / "actual-command-failure.json").read_bytes()
                )
                assert failure["exit_code"] != 0 and failure["wall_seconds"] < 5
                errors = json.loads((base / "start-error.json").read_bytes())["errors"]
                assert any(
                    item["reason"] == "root_gateway_cold_ready_incomplete"
                    for item in errors
                ), errors
            else:
                case = backend._saved(grant)
                assert (case / "gateway-cold-ready.json").exists()
                loss = json.loads((base / "gateway-loss-control.json").read_bytes())
                assert loss["exit_code"] != 0
                if scenario == "gateway-exits-during-create":
                    assert result["status"] == 503, result
                    assert (case / "container.json").exists()
                    assert not (case / "worker.json").exists()
                    assert "start" not in backend.public_docker_calls
                    errors = json.loads((base / "start-error.json").read_bytes())[
                        "errors"
                    ]
                    assert any(
                        item["reason"] == "root_gateway_lifetime_changed"
                        for item in errors
                    )
                else:
                    assert (
                        result["status"] == 200 and result["observed_status"] == 503
                    ), result
                    assert (case / "worker.json").exists()
                    assert "start" in backend.public_docker_calls
                    errors = json.loads((base / "observe-error.json").read_bytes())[
                        "errors"
                    ]
                    assert any(
                        item["reason"] == "root_gateway_lifetime_changed"
                        for item in errors
                    )
                assert (case / "execution-fenced.json").exists()
                assert (case / "owner-revoked.json").exists()
                assert not (case / "finished.json").exists()
                product.store(base / "docker-calls.json", backend.public_docker_calls)
            if scenario.startswith("cleanup-"):
                case = backend._saved(grant)
                custody = json.loads(
                    (case / "gateway-cleanup-custody.json").read_bytes()
                )
                assert custody["child"]["pid"] == cold["pid"]
                if holding_descendant:
                    family = []
                    for raw in (group / "gateway/cgroup.procs").read_text().split():
                        pid = int(raw)
                        namespace = Path(f"/proc/{pid}/ns/user").stat()
                        descriptors = [
                            int(entry.name)
                            for entry in Path(f"/proc/{pid}/fd").iterdir()
                            if os.readlink(entry) == f"socket:[{custody['kernel_ino']}]"
                        ]
                        assert descriptors and (namespace.st_dev, namespace.st_ino) == (
                            custody["namespace"]["dev"],
                            custody["namespace"]["ino"],
                        )
                        family.append(
                            {
                                "pid": pid,
                                "ticks": product._ticks(pid),
                                "socket_descriptors": descriptors,
                                "namespace": {
                                    "dev": namespace.st_dev,
                                    "ino": namespace.st_ino,
                                },
                                "cgroup": Path(f"/proc/{pid}/cgroup").read_text(),
                                "executable_sha256": digest(f"/proc/{pid}/exe"),
                            }
                        )
                    assert len(family) >= 2 and cold["pid"] in [
                        p["pid"] for p in family
                    ]
                    product.store(base / "live-synthetic-gateway-family.json", family)
                if scenario == "cleanup-guard":
                    custody_attacks(base, cold["pid"], custody)
                if scenario == "cleanup-normal":
                    identity = json.loads((case / "container.json").read_bytes())["id"]
                    backend._docker("wait", identity)
                    closed = backend.observe(
                        {"grant": grant, "worker": json.loads(result["response"])}
                    )
                    assert closed["state"] == "finished" and closed["exit_code"] == 0
                    product.store(base / "normal-close.json", closed)
                elif scenario == "cleanup-guard":
                    guard = json.loads((case / "guard-intent.json").read_bytes())
                    from linux_service_guard import _manager

                    with _manager(backend) as manager:

                        def stop(message):
                            manager._basic(message, "s", guard["unit"])
                            manager._basic(message, "s", "replace")

                        job = manager._call("StopUnit", stop)
                    deadline = time.monotonic() + 35
                    namespace_members = []
                    while (
                        not (case / "cleanup.json").exists()
                        and time.monotonic() < deadline
                    ):
                        for entry in Path("/proc").iterdir():
                            if not entry.name.isdecimal():
                                continue
                            try:
                                info = (entry / "ns/user").stat()
                                if (info.st_dev, info.st_ino) == (
                                    custody["namespace"]["dev"],
                                    custody["namespace"]["ino"],
                                ):
                                    fields = (
                                        (entry / "stat")
                                        .read_text()
                                        .rsplit(") ", 1)[1]
                                        .split()
                                    )
                                    observation = {
                                        "pid": int(entry.name),
                                        "ticks": fields[19],
                                        "state": fields[0],
                                        "fd_names": [
                                            p.name for p in (entry / "fd").iterdir()
                                        ],
                                        "cgroup": (entry / "cgroup").read_text(),
                                    }
                                    if observation not in namespace_members:
                                        namespace_members.append(observation)
                            except FileNotFoundError:
                                continue
                        time.sleep(0.05)
                    product.store(
                        base / "guard-namespace-observations.json", namespace_members
                    )
                    product.store(
                        base / "guard-stop-job.json",
                        {"unit": guard["unit"], "job": job},
                    )
                    assert (case / "cleanup.json").exists(), (
                        "guard stop-post did not retire gateway"
                    )
                    product.store(
                        base / "guard-stop-post.json",
                        {"unit": guard["unit"], "cleanup": True},
                    )
                elif scenario == "cleanup-lease":
                    changed = json.loads(lease_path.read_bytes()) | {"expires_at_ms": 1}
                    lease_path.unlink()
                    product.store(lease_path, changed)
                    deadline = time.monotonic() + 35
                    while (
                        not (case / "cleanup.json").exists()
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.05)
                    assert (case / "cleanup.json").exists(), (
                        "lease-loss guard did not retire gateway"
                    )
                    product.store(
                        base / "lease-loss.json",
                        {"cleanup": True, "owned_lease_expired": True},
                    )
                elif scenario == "cleanup-owner":
                    product.store(
                        base / "owner-loss-control.json",
                        {
                            "pid": os.getpid(),
                            "ticks": product._ticks(os.getpid()),
                            "case": str(case),
                            "grant": grant,
                            "custody": custody,
                        },
                    )
                    os.kill(os.getpid(), signal.SIGKILL)
                elif scenario in ("cleanup-missing-inode", "cleanup-replaced-inode"):
                    # Preserve the exact fresh inode under an owned alternative name.
                    path = Path(custody["socket"]["path"])
                    path.rename(path.with_suffix(".preserved-missing-control"))
                    if scenario == "cleanup-replaced-inode":
                        replacement = socket.socket(socket.AF_UNIX)
                        replacement.bind(str(path))
                        replacement.close()
                elif scenario == "cleanup-changed-lineage":
                    path = case / "gateway-released.json"
                    changed = json.loads(path.read_bytes()) | {
                        "prepared_sha256": "0" * 64
                    }
                    path.unlink()
                    product.store(path, changed)
                elif scenario == "cleanup-daemon-outage":
                    original_docker = backend._docker

                    def unavailable(*args):
                        if args[:2] == ("container", "ls"):
                            raise product.SupervisorRefused(
                                "fixture_owned_daemon_unavailable"
                            )
                        return original_docker(*args)

                    backend._docker = unavailable
            if joined is None:
                assert not calls
            elif joined.mode != "missing-classifier":
                assert len(calls) == (11 if joined.mode == "success" else 14), calls
                joined.verify_restart()
                assert product._owner_alive(cold["pid"], cold["start_ticks"])
                assert digest(f"/proc/{cold['pid']}/exe") == cfg["gateway_executable_sha256"]
                product.store(base / "joined-provider-calls.json", joined.calls)
            server.shutdown()
    finally:
        product.subprocess.Popen = original_popen
        os.close(helper_log)
        if grant is None and (result_dir / "prepared.json").exists():
            grant = json.loads((result_dir / "prepared.json").read_bytes())
        if grant is not None:
            try:
                backend.revoke({"grant": grant})
            except Exception as error:
                product.store(base / "cleanup-error.json", error_record(error))
                print("cleanup-error", error_record(error), flush=True)
                expected_revocation_loss = (
                    scenario == "cleanup-revoke-unknown"
                    and isinstance(error, product.LinuxRunnerRefused)
                    and str(error) == "root_launch_outcome_unknown"
                )
                if (
                    not isinstance(error, product.SupervisorRefused)
                    and not expected_revocation_loss
                ):
                    raise
            case = backend._saved(grant)
            assert (case / "execution-fenced.json").exists()
            if scenario != "cleanup-revoke-unknown":
                assert (case / "owner-revoked.json").exists()
            assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
            for process in backend.gateway_children.values():
                assert process.poll() is not None
            assert all(
                not product._owner_alive(item["pid"], item["ticks"])
                for item in helper_children
            )
            product.store(
                base / "helper-terminal.json",
                {"observed_children": helper_children, "live_children_absent": True},
            )
            if not (case / "gateway-bound.json").exists():
                product.store(
                    base / "early-refusal.json",
                    {
                        "grant_sha256": product.sha(grant),
                        "http_calls": len(calls),
                        "cgroup_preserved": str(group),
                        "gateway_bound": False,
                    },
                )
                bound = None
            else:
                bound = json.loads((case / "gateway-bound.json").read_bytes())
            if scenario in (
                "cleanup-missing-inode",
                "cleanup-replaced-inode",
                "cleanup-changed-lineage",
                "cleanup-daemon-outage",
            ):
                assert not (case / "cleanup.json").exists(), (
                    "unknown resource cleanup incorrectly acknowledged"
                )
                assert not (case / "finished.json").exists(), "unknown cleanup finished"
                expected_reason = {
                    "cleanup-missing-inode": "root_gateway_socket_absence_unknown",
                    "cleanup-replaced-inode": "root_gateway_created_identity_changed",
                    "cleanup-changed-lineage": "root_gateway_cleanup_custody_changed",
                    "cleanup-daemon-outage": "fixture_owned_daemon_unavailable",
                }[scenario]
                errors = json.loads((base / "cleanup-error.json").read_bytes())["errors"]
                assert any(
                    item["type"] == "SupervisorRefused"
                    and item["reason"] == expected_reason
                    for item in errors
                ), ("cleanup refused for an unrelated reason", scenario, errors)
                product.store(
                    base / "negative-cleanup.json",
                    {"scenario": scenario, "cleanup_acknowledged": False},
                )
            if scenario == "cleanup-revoke-unknown":
                assert (case / "cleanup.json").exists() and not (
                    case / "owner-revoked.json"
                ).exists()
                assert not (case / "finished.json").exists()
            if bound is not None and scenario in (
                "positive",
                "cleanup-normal",
                "cleanup-guard",
                "cleanup-lease",
                "cleanup-revoke-unknown",
                "gateway-exits-during-create",
                "gateway-exits-before-observe",
            ):
                assert (case / "cleanup.json").exists(), (
                    "qualified handed gateway cleanup missing"
                )
                assert not os.path.lexists(bound["socket"]["path"]), (
                    "handed socket retained"
                )
                assert not (group / "gateway").exists(), "gateway cgroup leaf retained"
                if holding_descendant:
                    family = json.loads(
                        (base / "live-synthetic-gateway-family.json").read_bytes()
                    )
                    assert all(
                        not Path(f"/proc/{entry['pid']}").exists() for entry in family
                    ), "synthetic family PID retained"
                product.store(
                    base / "cleanup-terminal.json",
                    {
                        "socket_absent": bound["socket"],
                        "leaf_absent": str(group / "gateway"),
                        "cleanup": json.loads((case / "cleanup.json").read_bytes()),
                        "http_calls": len(calls),
                        "scenario": scenario,
                    },
                )
                bound = None
            if bound is not None and scenario in (
                "cleanup-missing-inode",
                "cleanup-replaced-inode",
            ):
                assert (
                    Path(bound["socket"]["path"])
                    .with_suffix(".preserved-missing-control")
                    .exists()
                )
                bound = None
            if bound is not None:
                info = os.stat(bound["socket"]["path"], follow_symlinks=False)
                assert (info.st_dev, info.st_ino) == (
                    bound["socket"]["dev"],
                    bound["socket"]["ino"],
                )
                assert not (case / "cleanup.json").exists()
                before = json.loads((base / "gateway-before.json").read_bytes())
                after = {}
                for path in Path("/var/lib/sfactory-harness/gw").iterdir():
                    item = path.lstat()
                    after[path.name] = {
                        "dev": item.st_dev,
                        "ino": item.st_ino,
                        "mode": item.st_mode,
                        "uid": item.st_uid,
                        "gid": item.st_gid,
                    }
                assert all(
                    after.get(name) == metadata for name, metadata in before.items()
                ), "preexisting gateway inode changed"
                assert grant["attempt_id"][4:] + ".sock" not in before
                product.store(base / "gateway-after.json", after)

                product.store(
                    base / "terminal.json",
                    {
                        "root_pid": backend_pid,
                        "root_ticks": product._ticks(backend_pid),
                        "grant_sha256": product.sha(grant),
                        "gateway_joined": True,
                        "http_calls": len(calls),
                        "socket_preserved": bound["socket"],
                        "cgroup_preserved": str(group),
                        "production_cleanup_qualified": False,
                        "scenario": scenario,
                    },
                )
        if joined is not None:
            before = json.loads((base / "gateway-before.json").read_bytes())
            after = {}
            for path in Path("/var/lib/sfactory-harness/gw").iterdir():
                info = path.lstat()
                after[path.name] = {"dev": info.st_dev, "ino": info.st_ino,
                                    "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid}
            assert all(after.get(name) == metadata for name, metadata in before.items())
            if not (base / "gateway-after.json").exists():
                product.store(base / "gateway-after.json", after)
        for child in children:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        upstream.shutdown()
        if joined is not None:
            joined.finish()


if __name__ == "__main__":
    main(
        *(Path(p) for p in sys.argv[1:4]),
        scenario=sys.argv[4] if len(sys.argv) == 5 else "positive",
    )
