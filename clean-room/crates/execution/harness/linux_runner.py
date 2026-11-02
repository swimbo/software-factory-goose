"""Generic Linux Runner integration with a protected Root supervisor.

Source contract only until the root daemon, observed launch recipe and production
owner/usage path are installed and admitted. No caller flag opens live admission.
The untrusted Goose process receives only the Unix worker protocol; it cannot
call this root client, spending collector or independent evaluator.
"""

from contextlib import ExitStack
import copy
import hashlib
import http.client
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import threading
import time

from benchmark_acceptance import contract, evaluate as independent_evaluate
from container_evaluator import DockerEvaluator
from factory_harness import Broker, Denied, Profile, canonical
from harness_session import CandidateSession
from linux_goose_runtime import LINUX_GOOSE_SHA256, LinuxWorkerRelay
from protected_goose_runtime import (
    BaselineSession,
    BoundedWorkspace,
    ModelRelay,
    ProtectedGooseAdapter,
    profile_fingerprints,
    read_private,
    sha,
    store_private,
)
from protected_spending_control import PrivateSpendingClient, _decode


class LinuxRunnerRefused(Denied):
    pass


def _require(condition, reason):
    if not condition:
        raise LinuxRunnerRefused(reason)


def _file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _integer(value, low, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def recipe(
    *,
    suite_sha256,
    config_sha256,
    profiles,
    script_host_sha256,
    normalizer_sha256,
    broker_uid,
    worker_uid,
    max_runtime_ms=180000,
):
    _require(
        all(
            _digest(v)
            for v in (
                suite_sha256,
                config_sha256,
                script_host_sha256,
                normalizer_sha256,
            )
        )
        and type(profiles) is dict
        and set(profiles) == {"baseline", "candidate"}
        and all(_digest(v) for v in profiles.values())
        and _integer(broker_uid, 1, 2**31 - 1)
        and _integer(worker_uid, 1, 2**31 - 1)
        and worker_uid == 2001
        and broker_uid != worker_uid
        and _integer(max_runtime_ms, 1, 180000),
        "invalid_linux_recipe",
    )
    return dict(
        schema=1,
        purpose="sfactory-harness-linux-v1",
        suite_sha256=suite_sha256,
        config_sha256=config_sha256,
        profiles=copy.deepcopy(profiles),
        goose_sha256=LINUX_GOOSE_SHA256,
        script_host_sha256=script_host_sha256,
        normalizer_sha256=normalizer_sha256,
        broker_uid=broker_uid,
        worker_uid=worker_uid,
        max_runtime_ms=max_runtime_ms,
        candidate_enabled=False,
    )


def linux_profiles(goose, host, normalizer, **configuration):
    parent = profile_fingerprints(goose, host, normalizer, **configuration)
    code = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in (
            "linux_runner.py",
            "linux_goose_runtime.py",
            "linux_worker.py",
            "linux_supervisor.py",
            "linux_service_guard.py",
            "linux_worker_image.py",
            "linux-worker.Dockerfile",
        )
    }
    return {
        variant: sha(
            dict(schema=2, parent=profile, code=code, worker_protocol="unix-json-v1")
        )
        for variant, profile in parent.items()
    }


def validate_attempt(attempt, admission, launch_recipe):
    _require(
        type(attempt) is dict
        and type(admission) is dict
        and set(admission) == {"attempt_id", "status", "authority_receipt_sha256"},
        "invalid_linux_admission",
    )
    identity = attempt.get("attempt_id")
    _require(
        isinstance(identity, str)
        and re.fullmatch(r"run_[0-9a-f]{64}", identity) is not None
        and attempt.get("suite_sha256") == launch_recipe["suite_sha256"]
        and attempt.get("config_sha256") == launch_recipe["config_sha256"]
        and attempt.get("goose_build") == LINUX_GOOSE_SHA256
        and attempt.get("profile")
        == launch_recipe["profiles"].get(attempt.get("variant"))
        and attempt.get("model") == "auto"
        and _digest(attempt.get("route"))
        and type(attempt.get("budget")) is int
        and attempt["budget"] == 750000
        and type(attempt.get("daily_cap")) is int
        and attempt["daily_cap"] == 5000000
        and admission.get("attempt_id") == identity
        and admission.get("status") == "allowed"
        and _digest(admission.get("authority_receipt_sha256")),
        "linux_attempt_binding_changed",
    )
    return identity


def validate_grant(grant, attempt, admission, launch_recipe, root, *, now_ms):
    fields = {
        "schema",
        "attempt_id",
        "attempt_sha256",
        "admission_sha256",
        "recipe_sha256",
        "grant_id",
        "issued_at_ms",
        "expires_at_ms",
        "worker_uid",
        "broker_uid",
        "boot_id",
        "cgroup_dev",
        "cgroup_ino",
        "cgroup_path",
        "workspace_path",
        "relay_path",
    }
    expected_recipe = recipe(
        **{
            key: launch_recipe[key]
            for key in (
                "suite_sha256",
                "config_sha256",
                "profiles",
                "script_host_sha256",
                "normalizer_sha256",
                "broker_uid",
                "worker_uid",
                "max_runtime_ms",
            )
        }
    )
    _require(
        launch_recipe == expected_recipe
        and type(launch_recipe["schema"]) is int
        and launch_recipe["candidate_enabled"] is False
        and type(grant) is dict
        and set(grant) == fields,
        "invalid_linux_grant",
    )
    identity = validate_attempt(attempt, admission, launch_recipe)
    case = Path(root) / identity
    _require(
        grant["schema"] == 1
        and type(grant["schema"]) is int
        and grant["attempt_id"] == identity
        and grant["attempt_sha256"] == sha(attempt)
        and grant["admission_sha256"] == sha(admission)
        and grant["recipe_sha256"] == sha(launch_recipe)
        and _digest(grant["grant_id"])
        and all(
            _integer(grant[k], 1)
            for k in ("issued_at_ms", "expires_at_ms", "cgroup_dev", "cgroup_ino")
        )
        and grant["issued_at_ms"] <= now_ms < grant["expires_at_ms"]
        and grant["expires_at_ms"] - grant["issued_at_ms"]
        <= launch_recipe["max_runtime_ms"]
        and _integer(grant["worker_uid"], 1, 2**31 - 1)
        and _integer(grant["broker_uid"], 1, 2**31 - 1)
        and grant["worker_uid"] == launch_recipe["worker_uid"]
        and grant["broker_uid"] == launch_recipe["broker_uid"]
        and isinstance(grant["boot_id"], str)
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", grant["boot_id"]
        )
        is not None
        and grant["cgroup_path"]
        == "/sys/fs/cgroup/sfactoryharness" + identity[4:] + ".slice"
        and grant["workspace_path"] == str(case / "work")
        and grant["relay_path"] == str(case / "relay.sock"),
        "linux_grant_binding_changed",
    )
    return copy.deepcopy(grant)


def validate_worker(value, grant, *, host_network):
    _require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "grant_sha256",
            "pid",
            "start_ticks",
            "worker_uid",
            "no_new_privs",
            "seccomp",
            "network_dev",
            "network_ino",
            "boot_id",
            "cgroup_dev",
            "cgroup_ino",
        },
        "invalid_linux_worker_observation",
    )
    _require(
        value["schema"] == 1
        and type(value["schema"]) is int
        and value["grant_sha256"] == sha(grant)
        and all(
            _integer(value[k], 1)
            for k in ("pid", "start_ticks", "network_dev", "network_ino")
        )
        and _integer(value["worker_uid"], 1, 2**31 - 1)
        and _integer(value["cgroup_dev"], 1)
        and _integer(value["cgroup_ino"], 1)
        and value["worker_uid"] == grant["worker_uid"]
        and value["no_new_privs"] == 1
        and type(value["no_new_privs"]) is int
        and value["seccomp"] == 2
        and type(value["seccomp"]) is int
        and (value["network_dev"], value["network_ino"]) != host_network
        and all(value[k] == grant[k] for k in ("boot_id", "cgroup_dev", "cgroup_ino")),
        "linux_worker_observation_changed",
    )
    return copy.deepcopy(value)


class PrivateRootSupervisorClient(PrivateSpendingClient):
    """Root-owned fixed socket, kernel Root peer, broker-only caller; never TCP.

    The same protected ext4/no-ACL ancestor checks as spending ingress apply.
    Root must provision this socket separately; its backend remains a launch gate.
    """

    def __init__(self, path, *, broker_uid):
        _require(
            sys.platform == "linux"
            and _integer(broker_uid, 1, 2**31 - 1)
            and os.geteuid() == broker_uid,
            "root_launch_identity_unavailable",
        )
        self.path = Path(path)
        _require(
            self.path.is_absolute() and ".." not in self.path.parts,
            "root_launch_path_unavailable",
        )
        self.service_uid, self.broker_uid, self.owner = 0, broker_uid, "harness-launch"
        self.identity = self._check_path()

    def __call__(self, method, body):
        _require(
            method
            in (
                "admit",
                "scope_preimage_v2",
                "gateway_peer_v1",
                "authorize_tool",
                "close",
                "prepare",
                "start",
                "observe",
                "revoke",
                "reconcile",
            )
            and os.geteuid() == self.broker_uid
            and type(body) is dict,
            "root_launch_role_denied",
        )
        return self._request("/harness-launch/" + method, body)

    def _request(self, path, body):
        raw = canonical(body).encode()
        _require(
            len(raw) <= 131072 and self._check_path() == self.identity,
            "root_launch_socket_changed",
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        connection = None
        expired = threading.Event()

        def interrupt():
            expired.set()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(5, interrupt)
        timer.daemon = True
        timer.start()
        try:
            client.connect(str(self.path))
            _, uid, _ = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            _require(
                uid == self.service_uid and self._check_path() == self.identity,
                "root_launch_peer_changed",
            )

            class UnixOnly(http.client.HTTPConnection):
                def connect(self):
                    raise LinuxRunnerRefused("root_launch_reconnect_denied")

            connection = UnixOnly("localhost", timeout=5)
            connection.sock = client
            connection.request(
                "POST",
                path,
                body=raw,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            lengths = response.headers.get_all("Content-Length", [])
            _require(
                response.status == 200
                and len(lengths) == 1
                and len(lengths[0]) <= 6
                and lengths[0].isascii()
                and lengths[0].isdecimal()
                and 0 < int(lengths[0]) <= 32768
                and response.headers.get("Transfer-Encoding") is None
                and response.headers.get("Content-Encoding") in (None, "identity")
                and response.headers.get_content_type() == "application/json",
                "root_launch_outcome_unknown",
            )
            result = response.read(32769)
            _require(
                not expired.is_set() and len(result) == int(lengths[0]),
                "root_launch_outcome_unknown",
            )
            return _decode(result)
        except LinuxRunnerRefused:
            raise
        except Exception:
            raise LinuxRunnerRefused("root_launch_outcome_unknown") from None
        finally:
            timer.cancel()
            timer.join(timeout=5)
            if connection is not None:
                connection.close()
            else:
                client.close()


class RootLaunchBridge:
    """JournaledControl.launch API over the same authenticated Root endpoint."""

    def __init__(self, client, launch_recipe):
        _require(
            type(client) is PrivateRootSupervisorClient,
            "protected_root_client_required",
        )
        self.client, self.recipe = client, copy.deepcopy(launch_recipe)

    def admit(self, attempt):
        return self.client(
            "admit", {"attempt": attempt, "recipe_sha256": sha(self.recipe)}
        )

    def authorize_tool(self, attempt, scope_sha256, name, arguments_sha256):
        return self.client(
            "authorize_tool",
            {
                "attempt": attempt,
                "scope_sha256": scope_sha256,
                "name": name,
                "arguments_sha256": arguments_sha256,
            },
        )

    def close(self, attempt, scope_sha256):
        reply = self.client("close", {"attempt": attempt, "scope_sha256": scope_sha256})
        _require(
            reply == {"scope_sha256": scope_sha256, "status": "closed"},
            "root_close_unknown",
        )

    def reconcile(self, attempt, record):
        return self.client(
            "reconcile",
            {"attempt": attempt, "record": record, "recipe_sha256": sha(self.recipe)},
        )


class _GatedRelay:
    def __init__(self, relay, ready, cancelled, deadline):
        self.relay, self.session, self.ready = relay, relay.session, ready
        self.cancelled, self.deadline = cancelled, deadline

    def _wait(self):
        while not self.ready.wait(0.01):
            _require(
                not self.cancelled.is_set() and time.monotonic() < self.deadline,
                "worker_identity_unavailable",
            )

    def exchange(self, body):
        self._wait()
        return self.relay.exchange(body)

    def tool(self, name, arguments):
        self._wait()
        return self.relay.tool(name, arguments)


class LinuxRunnerAdapter:
    """Runner interface; Root executes only the frozen generic recipe.

    The production JournaledControl gate remains binding. Constructing this class
    or returning a dictionary from an untrusted callback creates no authority.
    """

    normalize = ProtectedGooseAdapter.normalize

    def __init__(
        self,
        root,
        suite,
        *,
        goose,
        host,
        normalizer,
        control,
        supervisor,
        launch_recipe,
    ):
        _require(
            sys.platform == "linux" and type(supervisor) is PrivateRootSupervisorClient,
            "protected_linux_supervisor_required",
        )
        self.root, self.suite, self.control, self.supervisor = (
            Path(root).resolve(),
            suite,
            control,
            supervisor,
        )
        self.goose, self.host, self.normalizer = (
            Path(p).resolve() for p in (goose, host, normalizer)
        )
        self.recipe = copy.deepcopy(launch_recipe)
        _require(
            self.root.is_dir()
            and stat.S_IMODE(self.root.stat().st_mode) == 0o710
            and self.root.stat().st_uid == 0
            and self.root.stat().st_gid == self.recipe["broker_uid"]
            and os.geteuid() == self.recipe["broker_uid"]
            and _file_digest(self.goose) == LINUX_GOOSE_SHA256
            and _file_digest(self.host) == self.recipe["script_host_sha256"]
            and _file_digest(self.normalizer) == self.recipe["normalizer_sha256"]
            and suite["sha256"] == self.recipe["suite_sha256"],
            "linux_recipe_unavailable",
        )
        self.profiles = linux_profiles(
            self.goose,
            self.host,
            self.normalizer,
            model=control.config["model"],
            route=control.config["route_sha256"],
            max_request_bytes=control.config["max_request_bytes"],
            max_output_tokens=control.config["max_output_tokens"],
        )
        _require(
            self.profiles == self.recipe["profiles"] == control.config["profiles"],
            "linux_profile_changed",
        )
        self.grants, self.generated = {}, {}

    def _kernel_scope(self, grant, *, empty):
        _require(
            Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            == grant["boot_id"],
            "linux_boot_changed",
        )
        path = Path(grant["cgroup_path"])
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            _require(
                (metadata.st_dev, metadata.st_ino)
                == (grant["cgroup_dev"], grant["cgroup_ino"])
                and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0,
                "linux_cgroup_changed",
            )
            limits = {}
            for name in ("memory.max", "pids.max", "cpu.max"):
                control = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    raw = os.read(control, 4097)
                finally:
                    os.close(control)
                _require(len(raw) <= 4096, "linux_resource_limit_unavailable")
                limits[name] = raw.decode("ascii").strip()
            _require(
                limits["memory.max"].isdecimal()
                and 0 < int(limits["memory.max"]) <= 2 * 1024**3
                and limits["pids.max"].isdecimal()
                and 0 < int(limits["pids.max"]) <= 128,
                "linux_resource_limit_unavailable",
            )
            cpu = limits["cpu.max"].split()
            _require(
                len(cpu) == 2
                and all(v.isdecimal() for v in cpu)
                and 0 < int(cpu[0]) <= 2 * int(cpu[1])
                and int(cpu[1]) > 0,
                "linux_resource_limit_unavailable",
            )
            if empty:
                fd = os.open(
                    "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                try:
                    value = os.read(fd, 4097)
                finally:
                    os.close(fd)
                _require(
                    len(value) <= 4096 and b"populated 0" in value.splitlines(),
                    "linux_cleanup_unverified",
                )
        finally:
            os.close(descriptor)

    def admit(self, attempt):
        _require(
            attempt["attempt_id"] not in self.grants, "linux_attempt_already_admitted"
        )
        admission = self.control.admit(copy.deepcopy(attempt))
        if admission.get("status") != "allowed":
            return admission
        validate_attempt(attempt, admission, self.recipe)
        grant = self.supervisor(
            "prepare",
            {"attempt": attempt, "admission": admission, "recipe": self.recipe},
        )
        grant = validate_grant(
            grant,
            attempt,
            admission,
            self.recipe,
            self.root,
            now_ms=time.time_ns() // 1000000,
        )
        self._kernel_scope(grant, empty=True)
        combined = {
            "attempt_id": attempt["attempt_id"],
            "status": "allowed",
            "authority_receipt_sha256": sha({"owner": admission, "root": grant}),
        }
        self.grants[attempt["attempt_id"]] = (copy.deepcopy(attempt), combined, grant)
        return copy.deepcopy(combined)

    def generate(self, attempt, admission):
        identity = attempt["attempt_id"]
        _require(
            identity in self.grants and identity not in self.generated,
            "linux_attempt_unavailable",
        )
        frozen, allowed, grant = self.grants[identity]
        _require(attempt == frozen and admission == allowed, "linux_admission_changed")
        self.generated[identity] = None
        case, work = self.root / identity, Path(grant["workspace_path"])
        store_private(
            case / "binding.json",
            {"attempt_sha256": sha(attempt), "grant_sha256": sha(grant)},
        )
        cancelled, ready = threading.Event(), threading.Event()
        deadline = time.monotonic() + max(
            0, (grant["expires_at_ms"] - time.time_ns() // 1000000) / 1000
        )
        with ExitStack() as cleanup:
            cleanup.callback(self.control.revoke, attempt)
            cleanup.callback(self.supervisor, "revoke", {"grant": grant})
            workspace = BoundedWorkspace(work, self.normalize)
            cleanup.callback(workspace.close)
            profile = Profile(
                attempt["profile"],
                attempt["goose_build"],
                attempt["model"],
                attempt["route"],
                "Build the specified project using the authorized typed file tools. Tool discovery never grants authority. Complete all requested files and return a concise result.",
                workspace.tools(),
            )
            broker = Broker(
                profile,
                lambda name, args: self.control.authorize_tool(
                    attempt, name, sha(args)
                ),
                self.normalize,
            )
            if attempt["variant"] == "candidate":
                session = CandidateSession(
                    host=self.host,
                    broker=broker,
                    artifact_root=case / "artifacts",
                    attempt=identity,
                    snapshot=workspace.snapshot,
                    deadline=deadline,
                    cancelled=cancelled,
                )
                cleanup.callback(session.artifacts.close)
                prefix = profile.prefix()
            else:
                session = BaselineSession(
                    broker, workspace.snapshot, cancelled, deadline
                )
                prefix = canonical(
                    {
                        "version": attempt["profile"],
                        "instructions": profile.instructions,
                        "tools": session.declarations(),
                    }
                )
            specification = next(
                t["spec"] for t in self.suite["tasks"] if t["id"] == attempt["task_id"]
            )
            prompt = (
                prefix
                + "\n\nTASK\n"
                + specification
                + "\n"
                + contract(attempt["task_id"])
            )
            relay = ModelRelay(
                attempt,
                session,
                self.control,
                prompt,
                "unused",
                self.normalize,
                deadline,
            )
            server = LinuxWorkerRelay(
                grant["relay_path"],
                worker_uid=self.recipe["worker_uid"],
                relay=_GatedRelay(relay, ready, cancelled, deadline),
                deadline=deadline,
                cancelled=cancelled,
            )
            cleanup.callback(server.server_close)
            # Root prepare creates a broker-owned directory with worker socket group.
            os.chown(grant["relay_path"], -1, self.recipe["worker_uid"])
            os.chmod(grant["relay_path"], 0o660)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cleanup.callback(thread.join, timeout=5)
            cleanup.callback(server.shutdown)
            cleanup.callback(cancelled.set)
            start = time.monotonic()
            observed = self.supervisor(
                "start",
                {
                    "grant": grant,
                    "prompt": prompt,
                    "declarations_sha256": sha(session.declarations()),
                    "worker_protocol": "unix-json-v1",
                },
            )
            host = os.stat("/proc/self/ns/net")
            worker = validate_worker(
                observed, grant, host_network=(host.st_dev, host.st_ino)
            )
            self._kernel_scope(grant, empty=False)
            ready.set()
            while True:
                _require(time.monotonic() < deadline, "linux_attempt_deadline")
                if cancelled.is_set():
                    self.supervisor("revoke", {"grant": grant})
                status = self.supervisor("observe", {"grant": grant, "worker": worker})
                _require(
                    type(status) is dict and status.get("grant_sha256") == sha(grant),
                    "linux_observation_changed",
                )
                if status.get("state") == "finished":
                    _require(
                        set(status)
                        == {
                            "grant_sha256",
                            "state",
                            "worker",
                            "exit_code",
                            "timed_out",
                            "overflow",
                        }
                        and status["worker"] == worker
                        and type(status["exit_code"]) is int
                        and type(status["timed_out"]) is bool
                        and type(status["overflow"]) is bool,
                        "linux_terminal_observation_changed",
                    )
                    break
                _require(
                    status == {"grant_sha256": sha(grant), "state": "running"},
                    "linux_observation_changed",
                )
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            self._kernel_scope(grant, empty=True)
            outcome = (
                "completed"
                if status["exit_code"] == 0
                and not status["timed_out"]
                and not status["overflow"]
                and not relay.failed
                and relay.assistant is not None
                and not relay.assistant.get("tool_calls")
                else "failed"
            )
            if getattr(session.stalls, "stalled", False):
                outcome = "stalled"
            elif cancelled.is_set() and not relay.failed:
                outcome = "cancelled"
            artifact = workspace.snapshot()
            if not all(
                (work / name).is_file()
                for name in ("solution.py", "README.md", "test_solution.py")
            ):
                outcome = "failed"
            value = dict(
                attempt_id=identity,
                artifact_sha256=artifact,
                dispatch_manifest_sha256=sha(relay.records),
                call_ids=[r["call_id"] for r in relay.records],
                elapsed_ms=max(1, int((time.monotonic() - start) * 1000)),
                generation_receipt_sha256=sha(
                    {
                        "artifact": artifact,
                        "calls": relay.records,
                        "outcome": outcome,
                        "worker": worker,
                    }
                ),
                model=attempt["model"],
                route=attempt["route"],
                goose_build=attempt["goose_build"],
                profile=attempt["profile"],
                outcome=outcome,
                live=attempt["mode"] == "live",
            )
            store_private(case / "generation.json", value)
            store_private(
                case / "metrics.json",
                dict(
                    attempt_id=identity,
                    goose_build=attempt["goose_build"],
                    profile=attempt["profile"],
                    route=attempt["route"],
                    model=attempt["model"],
                    calls=relay.metrics,
                ),
            )
            self.generated[identity] = value
            return copy.deepcopy(value)

    def _saved(self, attempt, generation):
        case = self.root / attempt["attempt_id"]
        _require(
            read_private(case / "binding.json")["attempt_sha256"] == sha(attempt),
            "linux_attempt_changed",
        )
        saved = read_private(case / "generation.json")
        _require(saved == generation, "linux_generation_changed")
        return case, saved

    def evaluate(self, attempt, generation):
        case, saved = self._saved(attempt, generation)
        workspace = BoundedWorkspace(case / "work", self.normalize)
        try:
            _require(
                workspace.snapshot() == saved["artifact_sha256"],
                "linux_artifact_changed",
            )
        finally:
            workspace.close()
        result = independent_evaluate(
            attempt["task_id"],
            saved["artifact_sha256"],
            DockerEvaluator(case / "work", case / "evaluation"),
        )
        result["accepted"] = result["accepted"] and saved["outcome"] == "completed"
        result["evaluation_receipt_sha256"] = sha(
            {
                "independent_receipt": result["evaluation_receipt_sha256"],
                "generation_outcome": saved["outcome"],
                "accepted": result["accepted"],
            }
        )
        result["evaluator_build"] = sha(
            {
                name: hashlib.sha256(
                    Path(__file__).with_name(name).read_bytes()
                ).hexdigest()
                for name in (
                    "benchmark_acceptance.py",
                    "container_evaluator.py",
                    "container_eval_host.py",
                    "linux_runner.py",
                )
            }
        )
        return result | {"attempt_id": attempt["attempt_id"]}

    def collect(self, attempt, generation):
        self._saved(attempt, generation)
        return self.control.billing(attempt, generation)

    def reconcile(self, attempt, record):
        owner = self.control.reconcile(attempt, record)
        observed = self.supervisor(
            "reconcile",
            {"attempt": attempt, "record": record, "recipe_sha256": sha(self.recipe)},
        )
        _require(
            type(observed) is dict
            and set(observed)
            == {"attempt_id", "attempt_sha256", "state", "receipt_sha256"}
            and observed["attempt_id"] == attempt["attempt_id"]
            and observed["attempt_sha256"] == sha(attempt)
            and _digest(observed["receipt_sha256"]),
            "linux_reconciliation_unavailable",
        )
        _require(
            owner.get("status") == "not_dispatched"
            and observed["state"] == "not_started"
            and not (self.root / attempt["attempt_id"]).exists(),
            "linux_reconciliation_required",
        )
        return owner
