#!/usr/bin/env python3
"""Fixed-recipe Root supervisor; no production catalog is synthesized or installed.

A separately admitted Root publisher must provision exact frozen attempts, current
lease evidence, reviewed spending scopes and empty dedicated cgroups. Only then
can this backend execute a credential-free worker. Root intent/unknown records
are retained; lost start acknowledgements never authorize another launch.
"""

import copy
import hashlib
import http.server
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from linux_runner import (
    LinuxRunnerAdapter,
    LinuxRunnerRefused,
    PrivateRootSupervisorClient,
    _digest,
    _integer,
    recipe,
    validate_grant,
    validate_worker,
)
from protected_goose_runtime import sha
from linux_goose_runtime import LINUX_GOOSE_BYTES, LINUX_GOOSE_SHA256
from protected_spending_control import _decode, _no_acl
from factory_harness import canonical

from linux_worker_image import WORKER_IMAGE
from linux_service_guard import start_guard, check_guard

MOUNT_TARGETS = {
    "goose": "/goose",
    "worker": "/factory/linux_worker.py",
    "profile": "/factory/profile.json",
    "goose_profile": "/run/software-factory-goose/profile.json",
    "prompt": "/factory/prompt.txt",
    "relay": "/gate/relay.sock",
}


class SupervisorRefused(LinuxRunnerRefused):
    pass


def require(value, reason):
    if not value:
        raise SupervisorRefused(reason)


def inspect_gateway_peer(grant, pid, start_ticks, uid, executable_sha256):
    """Check a kernel-reported peer; this is not a launch or egress fence."""
    require(
        _integer(pid, 2, 2**31 - 1)
        and _integer(start_ticks, 1, 2**63 - 1)
        and _integer(uid, 1, 2**31 - 1)
        and _digest(executable_sha256),
        "root_gateway_peer_invalid",
    )
    base = Path("/proc") / str(pid)
    ticks = _ticks(pid)
    require(ticks == start_ticks, "root_gateway_peer_changed")
    path = grant["cgroup_path"].removeprefix("/sys/fs/cgroup")

    def snapshot():
        fields = dict(
            line.split(":", 1)
            for line in (base / "status").read_text().splitlines()
            if ":" in line
        )
        group = (base / "cgroup").read_text().strip().splitlines()
        require(
            fields.get("Uid", "").split() == [str(uid)] * 4
            and fields.get("NoNewPrivs", "").strip() == "1"
            and all(
                int(fields.get(key, "-1").strip(), 16) == 0
                for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
            )
            and len(group) == 1
            and group[0].startswith("0::")
            and (group[0][3:] == path or group[0][3:].startswith(path + "/")),
            "root_gateway_peer_changed",
        )
        return fields["Uid"], fields["NoNewPrivs"], tuple(group)

    before = snapshot()
    fd = os.open(base / "exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_mode & 0o022 == 0
            and 0 < info.st_size <= 536870912,
            "root_gateway_executable_changed",
        )
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            block = os.read(fd, min(65536, remaining))
            require(bool(block), "root_gateway_executable_changed")
            digest.update(block)
            remaining -= len(block)
        require(not os.read(fd, 1), "root_gateway_executable_changed")
        final = os.stat(base / "exe")
        require(
            digest.hexdigest() == executable_sha256
            and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            == (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            and _owner_alive(pid, ticks)
            and snapshot() == before,
            "root_gateway_peer_changed",
        )
    finally:
        os.close(fd)


def require_broker_pid_namespace(pid):
    """The broker's SO_PEERCRED PID and Root's /proc must use one namespace."""
    require(_integer(pid, 2, 2**31 - 1), "root_broker_pid_namespace_changed")
    proc_pid = int(Path("/proc/self/stat").read_text().split(" ", 1)[0])
    require(proc_pid == os.getpid(), "root_broker_pid_namespace_changed")
    broker = os.stat(Path("/proc") / str(pid) / "ns/pid")
    own = os.stat("/proc/self/ns/pid")
    require(
        (broker.st_dev, broker.st_ino) == (own.st_dev, own.st_ino),
        "root_broker_pid_namespace_changed",
    )


def factory_scope_digest(scope):
    """Reproduce the wallet's ordered Rust scope encoding; grants no authority."""
    fields = (
        "task",
        "attempt",
        "generation",
        "worker",
        "lease_sha256",
        "issued_at_ms",
        "expires_at_ms",
        "route",
    )
    route_fields = (
        "route_sha256",
        "review_sha256",
        "valid_from_ms",
        "valid_until_ms",
        "max_request_bytes",
        "max_output_tokens",
        "components",
    )
    require(
        type(scope) is dict and set(scope) == set(fields), "root_scope_preimage_invalid"
    )
    route = scope["route"]
    require(
        type(route) is dict
        and set(route)
        in (set(route_fields), set(route_fields) | {"usage_tariff_sha256"}),
        "root_scope_preimage_invalid",
    )

    def valid_id(value):
        return (
            isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9_\-.:/]{1,256}", value) is not None
        )

    def number(value, maximum):
        return type(value) is int and 1 <= value <= maximum

    require(
        all(valid_id(scope[k]) for k in ("task", "generation", "worker"))
        and number(scope["attempt"], 2**32 - 1)
        and _digest(scope["lease_sha256"])
        and number(scope["issued_at_ms"], 253402300799999)
        and number(scope["expires_at_ms"], 253402300799999)
        and scope["issued_at_ms"] < scope["expires_at_ms"]
        and _digest(route["route_sha256"])
        and _digest(route["review_sha256"])
        and (
            route.get("usage_tariff_sha256") is None
            or _digest(route["usage_tariff_sha256"])
        )
        and number(route["valid_from_ms"], 253402300799999)
        and number(route["valid_until_ms"], 253402300799999)
        and route["valid_from_ms"] < route["valid_until_ms"]
        and number(route["max_request_bytes"], 1048576)
        and number(route["max_output_tokens"], 1000000)
        and type(route["components"]) is list
        and 1 <= len(route["components"]) <= 32,
        "root_scope_preimage_invalid",
    )
    components = []
    seen, total = set(), 0
    for item in route["components"]:
        require(
            type(item) is dict
            and set(item) == {"id", "max_charge_microusd"}
            and valid_id(item["id"])
            and item["id"] not in seen
            and number(item["max_charge_microusd"], 2**64 - 1),
            "root_scope_preimage_invalid",
        )
        seen.add(item["id"])
        total += item["max_charge_microusd"]
        require(total <= 2**64 - 1, "root_scope_preimage_invalid")
        components.append(
            {"id": item["id"], "max_charge_microusd": item["max_charge_microusd"]}
        )
    ordered_route = {
        "route_sha256": route["route_sha256"],
        "review_sha256": route["review_sha256"],
    }
    if route.get("usage_tariff_sha256") is not None:
        ordered_route["usage_tariff_sha256"] = route["usage_tariff_sha256"]
    ordered_route.update({k: route[k] for k in route_fields[2:-1]})
    ordered_route["components"] = components
    ordered_scope = {k: scope[k] for k in fields[:-1]}
    ordered_scope["route"] = ordered_route
    raw = json.dumps(
        ordered_scope, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def validate_catalog(entry, lease, attempt, admission, launch_recipe, *, now_ms):
    require(
        type(entry) is dict
        and set(entry)
        == {
            "schema",
            "attempt",
            "admission_sha256",
            "recipe_sha256",
            "scope",
            "scope_sha256",
            "factory_task_id",
            "control_grant",
            "cgroup",
        }
        and entry["schema"] == 1
        and type(entry["schema"]) is int
        and entry["attempt"] == attempt
        and entry["admission_sha256"] == sha(admission)
        and entry["recipe_sha256"] == sha(launch_recipe)
        and _digest(entry["scope_sha256"]),
        "root_catalog_binding_changed",
    )
    control = entry["control_grant"]
    fields = {
        "status",
        "attempt_id",
        "attempt_sha256",
        "scope_sha256",
        "policy_sha256",
        "owner",
        "route_sha256",
        "expires_at_ms",
        "authority_receipt_sha256",
    }
    if attempt.get("cost_basis") == "audited_usage_rated":
        fields |= {"cost_basis", "tariff_sha256"}
    require(
        type(control) is dict
        and set(control) == fields
        and control["status"] == "allowed"
        and control["attempt_id"] == attempt["attempt_id"]
        and control["attempt_sha256"] == sha(attempt)
        and control["scope_sha256"] == entry["scope_sha256"]
        and control["route_sha256"] == attempt["route"]
        and _digest(control["policy_sha256"])
        and _digest(control["authority_receipt_sha256"])
        and isinstance(control["owner"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", control["owner"])
        is not None
        and _integer(control["expires_at_ms"], now_ms + 1)
        and admission
        == {
            key: control[key]
            for key in ("attempt_id", "status", "authority_receipt_sha256")
        }
        and (
            "tariff_sha256" not in control
            or (
                control["cost_basis"] == "audited_usage_rated"
                and control["tariff_sha256"] == attempt["tariff_sha256"]
            )
        ),
        "root_control_grant_changed",
    )
    scope = entry["scope"]
    require(
        type(scope) is dict
        and set(scope)
        == {
            "task",
            "attempt",
            "generation",
            "worker",
            "lease_sha256",
            "issued_at_ms",
            "expires_at_ms",
            "route",
        }
        and scope["task"] == entry["factory_task_id"]
        and re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", scope["task"]) is not None
        and re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", scope["generation"])
        is not None
        and _digest(scope["lease_sha256"])
        and _integer(scope["attempt"], 1, 2**32 - 1)
        and isinstance(scope["generation"], str)
        and isinstance(scope["worker"], str)
        and _integer(scope["issued_at_ms"], 1)
        and _integer(scope["expires_at_ms"], 1)
        and scope["issued_at_ms"] <= now_ms < scope["expires_at_ms"]
        and scope["route"].get("route_sha256") == attempt["route"],
        "root_scope_changed",
    )
    require(
        type(lease) is dict
        and set(lease)
        == {
            "schema",
            "attempt_sha256",
            "task",
            "generation",
            "worker",
            "lease_sha256",
            "issued_at_ms",
            "expires_at_ms",
            "boot_id",
        }
        and lease["schema"] == 1
        and type(lease["schema"]) is int
        and lease["attempt_sha256"] == sha(attempt)
        and all(
            lease[k] == scope[k]
            for k in ("task", "generation", "worker", "lease_sha256")
        )
        and _integer(lease["issued_at_ms"], 1)
        and _integer(lease["expires_at_ms"], 1)
        and lease["issued_at_ms"]
        <= now_ms
        < lease["expires_at_ms"]
        <= scope["expires_at_ms"],
        "root_lease_unavailable",
    )
    group = entry["cgroup"]
    require(
        type(group) is dict
        and set(group) == {"path", "dev", "ino", "boot_id"}
        and group["path"]
        == "/sys/fs/cgroup/sfactoryharness" + attempt["attempt_id"][4:] + ".slice"
        and _integer(group["dev"], 1)
        and _integer(group["ino"], 1)
        and group["boot_id"] == lease["boot_id"],
        "root_cgroup_changed",
    )
    return copy.deepcopy(entry)


def validate_catalog_manifest(value, suite_sha256, config_sha256):
    require(
        type(value) is dict
        and set(value) == {"schema", "suite_sha256", "config_sha256", "attempts"}
        and value["schema"] == 1
        and type(value["schema"]) is int
        and value["suite_sha256"] == suite_sha256
        and value["config_sha256"] == config_sha256
        and type(value["attempts"]) is list
        and len(value["attempts"]) == 120,
        "root_catalog_manifest_changed",
    )
    mapping, inverse, identities, pairs = {}, {}, {}, set()
    for slot in value["attempts"]:
        require(
            type(slot) is dict
            and set(slot)
            == {
                "attempt_id",
                "attempt_sha256",
                "task_id",
                "factory_task_id",
                "repeat",
                "variant",
            }
            and isinstance(slot["attempt_id"], str)
            and re.fullmatch(r"run_[0-9a-f]{64}", slot["attempt_id"]) is not None
            and _digest(slot["attempt_sha256"])
            and isinstance(slot["task_id"], str)
            and 0 < len(slot["task_id"]) <= 128
            and isinstance(slot["factory_task_id"], str)
            and re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", slot["factory_task_id"])
            is not None
            and _integer(slot["repeat"], 0, 2)
            and slot["variant"] in ("baseline", "candidate"),
            "root_catalog_slot_changed",
        )
        task, factory = slot["task_id"], slot["factory_task_id"]
        require(
            mapping.get(task, factory) == factory
            and inverse.get(factory, task) == task,
            "root_permanent_task_mapping_changed",
        )
        identity = (task, slot["repeat"], slot["variant"])
        require(
            slot["attempt_id"] not in identities and identity not in pairs,
            "root_catalog_slot_duplicate",
        )
        mapping[task] = factory
        inverse[factory] = task
        pairs.add(identity)
        identities[slot["attempt_id"]] = copy.deepcopy(slot)
    require(
        len(mapping) == 20 and len(inverse) == 20, "root_catalog_task_inventory_changed"
    )
    return identities


def docker_arguments(grant, *, goose, worker, profile, goose_profile, prompt, relay):
    require(_integer(grant["worker_uid"], 1, 2**31 - 1), "root_worker_identity_changed")
    uid = str(grant["worker_uid"])
    values = [
        "create",
        "--pull=never",
        "--name",
        "sfactory-harness-" + grant["attempt_id"][4:],
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
        uid + ":" + uid,
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
        Path(grant["cgroup_path"]).name,
        "--tmpfs",
        "/work:rw,nosuid,nodev,noexec,size=8m,nr_inodes=512,uid="
        + uid
        + ",gid="
        + uid
        + ",mode=0700",
        "--ulimit",
        "core=0:0",
        "--stop-timeout",
        "1",
        "--entrypoint",
        "/usr/local/bin/python3",
    ]
    for name, source in (
        ("goose", goose),
        ("worker", worker),
        ("profile", profile),
        ("goose_profile", goose_profile),
        ("prompt", prompt),
        ("relay", relay),
    ):
        target = MOUNT_TARGETS[name]
        require(
            isinstance(source, str)
            and source.startswith("/var/lib/sfactory-harness/")
            and source.endswith("/" + grant["attempt_id"] + "/mounts/" + name)
            and ".." not in Path(source).parts
            and "," not in source
            and "\n" not in source,
            "root_mount_changed",
        )
        values += [
            "--mount",
            "type=bind,src=" + source + ",dst=" + target + ",readonly",
        ]
    return values + [
        WORKER_IMAGE,
        "-I",
        "-B",
        "/factory/linux_worker.py",
    ]


MAX_LAUNCH_FILE_BYTES = 256 * 1024 * 1024


def stage_launch_source(fd, source, destination, expected_sha256=None):
    """Snapshot a held regular inode, or link its socket, into Root's private case.

    Docker/runc cannot bind a final /proc/PID/fd magic link on the qualified host.
    Root's exclusive destination stays named until the owned container is removed.
    """
    destination = Path(destination)
    parent = destination.parent.stat(follow_symlinks=False)
    require(
        os.geteuid() == 0
        and parent.st_uid == 0
        and stat.S_ISDIR(parent.st_mode)
        and stat.S_IMODE(parent.st_mode) == 0o700,
        "root_mount_staging_changed",
    )
    _no_acl(destination.parent)
    info = os.fstat(fd)
    created = False
    try:
        if stat.S_ISSOCK(info.st_mode):
            require(expected_sha256 is None, "root_mount_staging_changed")
            os.link(source, destination, follow_symlinks=False)
            created = True
            linked = destination.lstat()
            require(
                (linked.st_dev, linked.st_ino) == (info.st_dev, info.st_ino),
                "root_relay_changed",
            )
        else:
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_mode & 0o022 == 0
                and _digest(expected_sha256)
                and 0
                < info.st_size
                <= (
                    LINUX_GOOSE_BYTES
                    if expected_sha256 == LINUX_GOOSE_SHA256
                    else MAX_LAUNCH_FILE_BYTES
                ),
                "root_mount_source_changed",
            )
            readable = os.open("/proc/self/fd/" + str(fd), os.O_RDONLY | os.O_CLOEXEC)
            try:
                opened = os.fstat(readable)
                require(
                    (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                    "root_mount_source_changed",
                )
                output = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o400,
                )
                created = True
                try:
                    digest, size = hashlib.sha256(), 0
                    while chunk := os.read(readable, 65536):
                        size += len(chunk)
                        require(size <= info.st_size, "root_mount_source_changed")
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(output, view)
                            require(written > 0, "root_mount_storage_failed")
                            view = view[written:]
                    require(
                        size == info.st_size and digest.hexdigest() == expected_sha256,
                        "root_mount_source_changed",
                    )
                    os.fchmod(output, 0o444 | (info.st_mode & 0o111))
                    os.fsync(output)
                finally:
                    os.close(output)
            finally:
                os.close(readable)
        directory = os.open(
            destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return str(destination)
    except BaseException:
        if created:
            destination.unlink()
        raise


def protected(path, mode, *, maximum=131072, expected=None):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "root_path_changed")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:-1]:
            metadata = os.fstat(descriptor)
            require(
                metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
                "root_ancestor_changed",
            )
            _no_acl(descriptor)
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        require(
            metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
            "root_ancestor_changed",
        )
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor
        )
        try:
            info = os.fstat(fd)
            _no_acl(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode
                and 0 < info.st_size <= maximum,
                "root_file_changed",
            )
            data = os.read(fd, maximum + 1)
            current = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
            require(
                len(data) == info.st_size
                and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                "root_file_changed",
            )
            require(
                expected is None or hashlib.sha256(data).hexdigest() == expected,
                "root_file_digest_changed",
            )
            return data
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


def root_directory(path, *, gid=0, mode=0o700):
    info = os.lstat(path)
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == gid
        and stat.S_IMODE(info.st_mode) == mode,
        "root_directory_changed",
    )
    _no_acl(path)


def store(path, value, mode=0o600):
    raw = value if type(value) is bytes else canonical(value).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        pending = memoryview(raw)
        while pending:
            pending = pending[os.write(fd, pending) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RootOwnerClient(PrivateRootSupervisorClient):
    def __init__(self, path, service_uid):
        require(
            sys.platform == "linux"
            and os.geteuid() == 0
            and _integer(service_uid, 1, 2**31 - 1),
            "root_owner_identity_unavailable",
        )
        self.path = Path(path)
        self.service_uid = service_uid
        self.broker_uid = 0
        self.owner = "harness-root"
        self.identity = self._check_path()

    def admit(self, scope):
        require(os.geteuid() == 0, "root_owner_identity_unavailable")
        return self._request("/spending/admit_attempt", scope)

    def revoke(self, scope_sha256):
        require(
            os.geteuid() == 0 and _digest(scope_sha256),
            "root_owner_identity_unavailable",
        )
        return self._request("/spending/revoke", scope_sha256)


class RootSupervisor:
    _kernel_scope = LinuxRunnerAdapter._kernel_scope

    def __init__(self, configuration, *, cleanup_only=False):
        require(
            sys.platform == "linux" and os.geteuid() == 0, "root_supervisor_required"
        )
        self.configuration = Path(configuration)
        self.cfg = _decode(protected(self.configuration, 0o600))
        fields = {
            "schema",
            "recipe",
            "runtime_root",
            "catalog_root",
            "catalog_sha256",
            "state_root",
            "socket_path",
            "goose",
            "worker_program",
            "worker_program_sha256",
            "worker_image",
            "owner_socket",
            "owner_service_uid",
            "registry_gate",
            "registry_gate_sha256",
            "python",
            "python_sha256",
            "docker",
            "docker_sha256",
            "empty_docker_config",
            "guard_program",
            "guard_program_sha256",
            "supervisor_program",
            "supervisor_program_sha256",
            "systemd_library",
            "systemd_library_sha256",
        }
        require(
            (
                set(self.cfg) == fields
                and self.cfg["schema"] == 2
                or set(self.cfg)
                == fields | {"gateway_uid", "gateway_executable_sha256"}
                and self.cfg["schema"] == 3
            )
            and type(self.cfg["schema"]) is int
            and self.cfg["worker_image"] == WORKER_IMAGE,
            "root_configuration_changed",
        )
        self.recipe = self.cfg["recipe"]
        for key in ("runtime_root", "catalog_root", "state_root", "socket_path"):
            require(
                str(self.cfg[key]).startswith("/var/lib/sfactory-harness/")
                and ".." not in Path(self.cfg[key]).parts,
                "root_namespace_changed",
            )
        require(
            self.recipe
            == recipe(
                **{
                    k: self.recipe[k]
                    for k in (
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
            ),
            "root_recipe_changed",
        )
        require(
            self.cfg["owner_service_uid"]
            not in (0, self.recipe["broker_uid"], self.recipe["worker_uid"]),
            "root_role_alias",
        )
        if self.cfg["schema"] == 3:
            require(
                _integer(self.cfg["gateway_uid"], 1, 2**31 - 1)
                and self.cfg["gateway_uid"]
                not in (
                    self.recipe["broker_uid"],
                    self.recipe["worker_uid"],
                    self.cfg["owner_service_uid"],
                )
                and _digest(self.cfg["gateway_executable_sha256"]),
                "root_gateway_identity_invalid",
            )
        self.runtime, self.catalog, self.state = (
            Path(self.cfg[k]) for k in ("runtime_root", "catalog_root", "state_root")
        )
        root_directory(self.runtime, gid=self.recipe["broker_uid"], mode=0o710)
        root_directory(self.catalog)
        manifest = _decode(
            protected(
                self.catalog / "index.json", 0o600, expected=self.cfg["catalog_sha256"]
            )
        )
        self.slots = validate_catalog_manifest(
            manifest, self.recipe["suite_sha256"], self.recipe["config_sha256"]
        )
        root_directory(self.state)
        root_directory(Path(self.cfg["empty_docker_config"]))
        require(
            not os.listdir(self.cfg["empty_docker_config"]),
            "root_docker_config_not_empty",
        )
        protected(
            self.cfg["worker_program"],
            0o444,
            expected=self.cfg["worker_program_sha256"],
        )
        for name in ("python", "docker"):
            # Executables are Root-owned immutable source inputs, never argv from a worker.
            path = Path(self.cfg[name])
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_mode & 0o022 == 0,
                "root_executable_changed",
            )
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while raw := source.read(65536):
                    digest.update(raw)
            require(
                digest.hexdigest() == self.cfg[name + "_sha256"],
                "root_executable_changed",
            )
        if not cleanup_only:
            gate_path = Path(self.cfg["registry_gate"])
            protected(
                gate_path,
                0o444,
                maximum=1048576,
                expected=self.cfg["registry_gate_sha256"],
            )
            sys.path.insert(0, str(gate_path.parent))
            spec = importlib.util.spec_from_file_location(
                "root_harness_registry_gate", gate_path
            )
            self.gate = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.gate)
            self.owner = RootOwnerClient(
                self.cfg["owner_socket"], self.cfg["owner_service_uid"]
            )
        self.guard = threading.Lock()

    def _case(self, identity):
        require(
            isinstance(identity, str)
            and len(identity) == 68
            and identity.startswith("run_")
            and _digest(identity[4:]),
            "root_attempt_changed",
        )
        return self.state / identity

    def _catalog(self, attempt, admission):
        identity = attempt["attempt_id"]
        self._case(identity)
        require(
            identity in self.slots
            and self.slots[identity]["attempt_sha256"] == sha(attempt)
            and all(
                self.slots[identity][key] == attempt[key]
                for key in ("task_id", "repeat", "variant")
            ),
            "root_catalog_attempt_changed",
        )
        require(
            not os.path.lexists(self.catalog / (identity + ".revoked")),
            "root_lease_revoked",
        )
        entry = _decode(protected(self.catalog / (identity + ".json"), 0o600))
        lease = _decode(protected(self.catalog / (identity + ".lease.json"), 0o600))
        require(
            entry["factory_task_id"] == self.slots[identity]["factory_task_id"],
            "root_permanent_task_mapping_changed",
        )
        validate_catalog(
            entry,
            lease,
            attempt,
            admission,
            self.recipe,
            now_ms=time.time_ns() // 1000000,
        )
        require(
            lease["boot_id"]
            == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "root_boot_changed",
        )
        return entry, lease

    def _docker(self, *arguments, timeout=8):
        result = subprocess.run(
            [self.cfg["docker"], "--host", "unix:///run/docker.sock", *arguments],
            env={
                "PATH": "/usr/bin:/bin",
                "DOCKER_CONFIG": self.cfg["empty_docker_config"],
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
        )
        require(len(result.stdout) <= 131072, "root_docker_output_overflow")
        return result.stdout

    def _inspect(self, grant):
        value = json.loads(
            self._docker(
                "inspect",
                "--type",
                "container",
                "sfactory-harness-" + grant["attempt_id"][4:],
            )
        )
        require(type(value) is list and len(value) == 1, "root_container_changed")
        item = value[0]
        cfg = item["Config"]
        host = item["HostConfig"]
        require(
            item["Image"] == WORKER_IMAGE
            and cfg["Labels"].get("sfactory.harness.grant") == sha(grant)
            and cfg["Labels"].get("sfactory.harness.attempt") == grant["attempt_id"]
            and cfg["User"] == str(grant["worker_uid"]) + ":" + str(grant["worker_uid"])
            and host["NetworkMode"] == "none"
            and host["ReadonlyRootfs"] is True
            and host["Privileged"] is False
            and host["CapDrop"] == ["ALL"]
            and host["PidsLimit"] == 64
            and host["Memory"] == 1073741824
            and host["MemorySwap"] == 1073741824
            and host["NanoCpus"] == 1000000000
            and host["CgroupParent"] == Path(grant["cgroup_path"]).name
            and "no-new-privileges" in host["SecurityOpt"]
            and host["UsernsMode"] == "host"
            and host["IpcMode"] == "none"
            and set(host["Tmpfs"]) == {"/work"}
            and len([m for m in item["Mounts"] if m["Type"] == "bind"]) == 6
            and {m["Destination"] for m in item["Mounts"] if m["Type"] == "bind"}
            == set(MOUNT_TARGETS.values())
            and {
                m["Destination"]: m["Source"]
                for m in item["Mounts"]
                if m["Type"] == "bind"
            }
            == {
                target: str(self._case(grant["attempt_id"]) / "mounts" / name)
                for name, target in MOUNT_TARGETS.items()
            }
            and all(
                (m["Type"] == "bind" and m["RW"] is False)
                or (m["Type"] == "tmpfs" and m["Destination"] == "/work")
                for m in item["Mounts"]
            ),
            "root_container_changed",
        )
        return item

    def _saved(self, grant):
        case = self._case(grant["attempt_id"])
        require(
            _decode(protected(case / "grant.json", 0o600)) == grant,
            "root_grant_changed",
        )
        return case

    def admit(self, body):
        require(
            set(body) == {"attempt", "recipe_sha256"}
            and body["recipe_sha256"] == sha(self.recipe),
            "root_admission_changed",
        )
        attempt = body["attempt"]
        self._case(attempt["attempt_id"])
        with self.gate.admission(), self.guard:
            entry = _decode(
                protected(self.catalog / (attempt["attempt_id"] + ".json"), 0o600)
            )
            control = entry["control_grant"]
            admission = {
                key: control[key]
                for key in ("attempt_id", "status", "authority_receipt_sha256")
            }
            entry, _ = self._catalog(attempt, admission)
            require(
                self.owner.admit(entry["scope"]) == entry["scope_sha256"],
                "root_owner_admission_unknown",
            )
            return copy.deepcopy(control)

    def scope_preimage_v2(self, body):
        """Return a checked preimage, never a liveness or spending grant."""
        require(
            type(body) is dict
            and set(body) == {"attempt", "scope_sha256"}
            and type(body["attempt"]) is dict
            and _digest(body["scope_sha256"]),
            "root_scope_preimage_invalid",
        )
        attempt = body["attempt"]
        with self.gate.admission(), self.guard:
            case = self._case(attempt["attempt_id"])
            intent = _decode(protected(case / "prepare-intent.json", 0o600))
            require(intent["attempt"] == attempt, "root_scope_preimage_changed")
            grant = _decode(protected(case / "grant.json", 0o600))
            self._current(grant)
            entry, lease = self._catalog(attempt, intent["admission"])
            expected = body["scope_sha256"]
            route = entry["scope"]["route"]
            now = time.time_ns() // 1000000
            deadline = min(
                grant["expires_at_ms"],
                lease["expires_at_ms"],
                entry["control_grant"]["expires_at_ms"],
                entry["scope"]["expires_at_ms"],
                route["valid_until_ms"],
            )
            require(
                type(deadline) is int
                and now < deadline
                and not os.path.lexists(case / "owner-revoked.json")
                and not os.path.lexists(case / "finished.json")
                and route["valid_from_ms"] <= now < route["valid_until_ms"]
                and self._saved_scope(grant) == expected
                and entry["scope_sha256"] == expected
                and factory_scope_digest(entry["scope"]) == expected,
                "root_scope_preimage_changed",
            )
            return {
                "schema": 2,
                "scope_sha256": expected,
                "scope": copy.deepcopy(entry["scope"]),
                "root_deadline_ms": deadline,
            }

    def authorize_tool(self, body):
        require(
            set(body) == {"attempt", "scope_sha256", "name", "arguments_sha256"}
            and body["name"] in ("read_file", "write_file", "list_files")
            and _digest(body["arguments_sha256"]),
            "root_tool_changed",
        )
        attempt = body["attempt"]
        with self.gate.admission():
            case = self._case(attempt["attempt_id"])
            intent = _decode(protected(case / "prepare-intent.json", 0o600))
            require(intent["attempt"] == attempt, "root_tool_attempt_changed")
            entry, _ = self._catalog(attempt, intent["admission"])
            require(
                entry["scope_sha256"] == body["scope_sha256"], "root_tool_scope_changed"
            )
            grant = _decode(protected(case / "grant.json", 0o600))
            self._current(grant)
            require(
                self._worker(grant, self._inspect(grant))
                == _decode(protected(case / "worker.json", 0o600)),
                "root_tool_worker_changed",
            )
            return dict(
                attempt_sha256=sha(attempt),
                scope_sha256=body["scope_sha256"],
                name=body["name"],
                arguments_sha256=body["arguments_sha256"],
                allowed=True,
            )

    def gateway_peer_v1(self, body):
        """Recheck an authenticated broker's kernel-reported gateway peer."""
        require(
            type(body) is dict
            and set(body) == {"attempt", "scope_sha256", "pid", "start_ticks"}
            and type(body["attempt"]) is dict
            and _digest(body["scope_sha256"])
            and _integer(body["pid"], 2, 2**31 - 1)
            and _integer(body["start_ticks"], 1, 2**63 - 1),
            "root_gateway_peer_invalid",
        )
        require(self.cfg.get("schema") == 3, "root_gateway_peer_unconfigured")
        self.scope_preimage_v2(
            {"attempt": body["attempt"], "scope_sha256": body["scope_sha256"]}
        )
        with self.gate.admission(), self.guard:
            case = self._case(body["attempt"]["attempt_id"])
            grant = _decode(protected(case / "grant.json", 0o600))
            self._current(grant)
            require(
                self._saved_scope(grant) == body["scope_sha256"],
                "root_gateway_peer_changed",
            )
            self._kernel_scope(grant, empty=False)
            ready = check_guard(self, grant)
            require(
                ready["owner_pid"] == os.getpid()
                and ready["owner_ticks"] == _ticks(os.getpid()),
                "root_gateway_guard_owner_changed",
            )
            inspect_gateway_peer(
                grant,
                body["pid"],
                body["start_ticks"],
                self.cfg["gateway_uid"],
                self.cfg["gateway_executable_sha256"],
            )
            self._current(grant)
            self._kernel_scope(grant, empty=False)
            return {
                "verified": True,
                "pid": body["pid"],
                "start_ticks": body["start_ticks"],
                "scope_sha256": body["scope_sha256"],
            }

    def close(self, body):
        require(set(body) == {"attempt", "scope_sha256"}, "root_close_changed")
        attempt = body["attempt"]
        case = self._case(attempt["attempt_id"])
        intent = _decode(protected(case / "prepare-intent.json", 0o600))
        require(intent["attempt"] == attempt, "root_close_attempt_changed")
        grant = _decode(protected(case / "grant.json", 0o600))
        require(
            self._saved_scope(grant) == body["scope_sha256"], "root_close_scope_changed"
        )
        self.revoke({"grant": grant})
        return {"scope_sha256": body["scope_sha256"], "status": "closed"}

    def prepare(self, body):
        require(
            set(body) == {"attempt", "admission", "recipe"}
            and body["recipe"] == self.recipe,
            "root_prepare_changed",
        )
        attempt, admission = body["attempt"], body["admission"]
        with self.gate.admission(), self.guard:
            entry, lease = self._catalog(attempt, admission)
            case = self._case(attempt["attempt_id"])
            require(
                not os.path.lexists(case)
                and not os.path.lexists(self.runtime / attempt["attempt_id"]),
                "root_prepare_already_attempted",
            )
            os.mkdir(case, 0o700)
            store(case / "prepare-intent.json", body)
            # The actual owner repeats its existing registry gates and durable scope admission.
            require(
                self.owner.admit(entry["scope"]) == entry["scope_sha256"],
                "root_owner_admission_unknown",
            )
            group = entry["cgroup"]
            now = time.time_ns() // 1000000
            grant = dict(
                schema=1,
                attempt_id=attempt["attempt_id"],
                attempt_sha256=sha(attempt),
                admission_sha256=sha(admission),
                recipe_sha256=sha(self.recipe),
                grant_id=secrets.token_hex(32),
                issued_at_ms=now,
                expires_at_ms=min(
                    now + self.recipe["max_runtime_ms"], lease["expires_at_ms"]
                ),
                worker_uid=self.recipe["worker_uid"],
                broker_uid=self.recipe["broker_uid"],
                boot_id=group["boot_id"],
                cgroup_dev=group["dev"],
                cgroup_ino=group["ino"],
                cgroup_path=group["path"],
                workspace_path=str(self.runtime / attempt["attempt_id"] / "work"),
                relay_path=str(self.runtime / attempt["attempt_id"] / "relay.sock"),
            )
            validate_grant(
                grant, attempt, admission, self.recipe, self.runtime, now_ms=now
            )
            self._kernel_scope(grant, empty=True)
            runtime = self.runtime / attempt["attempt_id"]
            os.mkdir(runtime, 0o700)
            os.chown(runtime, grant["broker_uid"], grant["broker_uid"])
            os.mkdir(runtime / "work", 0o700)
            os.chown(runtime / "work", grant["broker_uid"], grant["broker_uid"])
            store(
                case / "owner-scope.json",
                {"grant_sha256": sha(grant), "scope_sha256": entry["scope_sha256"]},
            )
            store(case / "grant.json", grant)
            return grant

    def _current(self, grant):
        case = self._saved(grant)
        intent = _decode(protected(case / "prepare-intent.json", 0o600))
        self._catalog(intent["attempt"], intent["admission"])
        require(
            time.time_ns() // 1000000 < grant["expires_at_ms"]
            and not os.path.lexists(case / "stop.json"),
            "root_launch_expired_or_revoked",
        )
        return case

    def _worker(self, grant, item):
        pid = item["State"]["Pid"]
        require(
            item["State"]["Running"] is True and _integer(pid, 1),
            "root_worker_unavailable",
        )
        base = Path("/proc") / str(pid)
        fields = dict(
            line.split(":", 1)
            for line in (base / "status").read_text().splitlines()
            if ":" in line
        )
        uid = [int(x) for x in fields["Uid"].split()]
        require(uid == [grant["worker_uid"]] * 4, "root_worker_identity_changed")
        ticks = _ticks(pid)
        member = (base / "cgroup").read_text().strip().splitlines()
        path = grant["cgroup_path"].removeprefix("/sys/fs/cgroup")
        require(
            len(member) == 1
            and member[0].startswith("0::")
            and (member[0][3:] == path or member[0][3:].startswith(path + "/")),
            "root_worker_cgroup_changed",
        )
        net = os.stat(base / "ns/net")
        own = os.stat("/proc/self/ns/net")
        result = dict(
            schema=1,
            grant_sha256=sha(grant),
            pid=pid,
            start_ticks=ticks,
            worker_uid=uid[0],
            no_new_privs=int(fields["NoNewPrivs"]),
            seccomp=int(fields["Seccomp"]),
            network_dev=net.st_dev,
            network_ino=net.st_ino,
            boot_id=grant["boot_id"],
            cgroup_dev=grant["cgroup_dev"],
            cgroup_ino=grant["cgroup_ino"],
        )
        return validate_worker(result, grant, host_network=(own.st_dev, own.st_ino))

    def start(self, body):
        require(
            set(body) == {"grant", "prompt", "declarations_sha256", "worker_protocol"}
            and body["worker_protocol"] == "unix-json-v1"
            and isinstance(body["prompt"], str)
            and 0 < len(body["prompt"].encode()) <= 65536
            and _digest(body["declarations_sha256"]),
            "root_start_changed",
        )
        grant = body["grant"]
        with self.gate.admission(), self.guard:
            case = self._current(grant)
            require(
                not os.path.lexists(case / "start-intent.json"),
                "root_start_already_attempted",
            )
            intent = _decode(protected(case / "prepare-intent.json", 0o600))
            # Protected catalog publisher freezes exact generic prompt/declarations per attempt.
            contract = _decode(
                protected(self.catalog / (grant["attempt_id"] + ".launch.json"), 0o600)
            )
            require(
                set(contract)
                == {
                    "prompt_sha256",
                    "declarations_sha256",
                    "profile_sha256",
                    "max_output_tokens",
                }
                and contract["prompt_sha256"]
                == hashlib.sha256(body["prompt"].encode()).hexdigest()
                and contract["declarations_sha256"] == body["declarations_sha256"]
                and contract["profile_sha256"] == intent["attempt"]["profile"]
                and _integer(contract["max_output_tokens"], 1, 16384),
                "root_prompt_or_tools_changed",
            )
            store(case / "start-intent.json", body)
            profile = dict(
                schema=1,
                purpose=self.recipe["purpose"],
                worker_uid=grant["worker_uid"],
                broker_uid=grant["broker_uid"],
                goose_sha256=self.recipe["goose_sha256"],
                prompt_sha256=contract["prompt_sha256"],
                declarations_sha256=contract["declarations_sha256"],
                max_output_tokens=contract["max_output_tokens"],
                max_runtime_ms=self.recipe["max_runtime_ms"],
            )
            store(case / "profile.json", canonical(profile).encode(), 0o444)
            store(case / "prompt.txt", body["prompt"].encode(), 0o444)
            entry, _ = self._catalog(intent["attempt"], intent["admission"])
            goose_profile = dict(
                schema=1,
                profile="nuc-root-supervised-stdio-v1",
                task_id=entry["factory_task_id"],
                generation=entry["scope"]["generation"],
                recipe_sha256=sha(self.recipe),
                worker_uid=grant["worker_uid"],
            )
            store(case / "goose-profile.json", canonical(goose_profile).encode(), 0o444)
            start_guard(self, grant)
            mounts = case / "mounts"
            os.mkdir(mounts, 0o700)
            expected = dict(
                goose=self.recipe["goose_sha256"],
                worker=self.cfg["worker_program_sha256"],
                profile=hashlib.sha256(canonical(profile).encode()).hexdigest(),
                goose_profile=hashlib.sha256(
                    canonical(goose_profile).encode()
                ).hexdigest(),
                prompt=contract["prompt_sha256"],
            )
            descriptors = []
            try:
                paths = {}
                for name, path in (
                    ("goose", self.cfg["goose"]),
                    ("worker", self.cfg["worker_program"]),
                    ("profile", case / "profile.json"),
                    ("goose_profile", case / "goose-profile.json"),
                    ("prompt", case / "prompt.txt"),
                    ("relay", grant["relay_path"]),
                ):
                    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW)
                    descriptors.append(fd)
                    info = os.fstat(fd)
                    require(
                        (
                            name == "relay"
                            and stat.S_ISSOCK(info.st_mode)
                            and info.st_uid == grant["broker_uid"]
                            and info.st_gid == grant["worker_uid"]
                            and stat.S_IMODE(info.st_mode) == 0o660
                        )
                        or (
                            name != "relay"
                            and stat.S_ISREG(info.st_mode)
                            and info.st_uid == 0
                            and info.st_mode & 0o022 == 0
                        ),
                        "root_launch_source_changed",
                    )
                    paths[name] = stage_launch_source(
                        fd, path, mounts / name, expected.get(name)
                    )
                require(
                    self._docker("info", "--format", "{{.CgroupDriver}}")
                    .decode()
                    .strip()
                    == "systemd",
                    "root_cgroup_driver_unqualified",
                )
                image = json.loads(self._docker("image", "inspect", WORKER_IMAGE))[0]
                require(not image["Config"].get("Volumes"), "root_image_volume_changed")
                check_guard(self, grant)
                identity = (
                    self._docker(*docker_arguments(grant, **paths)).decode().strip()
                )
                require(_digest(identity), "root_create_unknown")
                store(case / "container.json", dict(id=identity))
                self._inspect(grant)
                self._current(grant)
                check_guard(self, grant)
                self._docker("start", identity)
                observed = self._worker(grant, self._inspect(grant))
                store(case / "worker.json", observed)
                return observed
            finally:
                for fd in descriptors:
                    os.close(fd)

    def _fence_execution(self, grant):
        # The daemon may be unavailable or holding a queued start. Keep the exact
        # dedicated parent frozen, including future arrivals, before querying it.
        self._saved(grant)
        require(
            Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            == grant["boot_id"],
            "root_fence_boot_changed",
        )
        fd = os.open(grant["cgroup_path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(
                (info.st_dev, info.st_ino) == (grant["cgroup_dev"], grant["cgroup_ino"])
                and info.st_uid == 0
                and info.st_mode & 0o022 == 0,
                "root_fence_cgroup_changed",
            )
            for name in ("cgroup.freeze", "cgroup.kill"):
                control = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(os.write(control, b"1") == 1, "root_fence_unverified")
                finally:
                    os.close(control)
            deadline = time.monotonic() + 1
            while True:
                values = {}
                for name in ("cgroup.freeze", "cgroup.events"):
                    control = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        values[name] = os.read(control, 4097)
                    finally:
                        os.close(control)
                require(
                    all(len(v) <= 4096 for v in values.values()),
                    "root_fence_unverified",
                )
                if (
                    values["cgroup.freeze"].strip() == b"1"
                    and b"populated 0" in values["cgroup.events"].splitlines()
                ):
                    break
                require(time.monotonic() < deadline, "root_fence_unverified")
                time.sleep(0.01)
        finally:
            os.close(fd)
        case = self._saved(grant)
        receipt = {"grant_sha256": sha(grant), "state": "execution_fenced"}
        if not os.path.lexists(case / "execution-fenced.json"):
            try:
                store(case / "execution-fenced.json", receipt)
            except FileExistsError:
                pass
        require(
            _decode(protected(case / "execution-fenced.json", 0o600)) == receipt,
            "root_fence_receipt_changed",
        )

    def _cleanup(self, grant):
        case = self._saved(grant)
        self._fence_execution(grant)
        name = "sfactory-harness-" + grant["attempt_id"][4:]
        # A successful daemon query distinguishes absence from an unavailable daemon.
        identities = (
            self._docker(
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "name=^/" + name + "$",
                "--format",
                "{{.ID}}",
            )
            .decode()
            .splitlines()
        )
        require(len(identities) <= 1, "root_cleanup_identity_changed")
        if identities:
            item = self._inspect(grant)
            require(item["Id"] == identities[0], "root_cleanup_identity_changed")
            self._docker("rm", "-f", item["Id"])
        elif os.path.lexists(case / "start-intent.json"):
            # An unacknowledged create can still be pending in the daemon. Do not
            # turn an empty listing into a successful cleanup receipt in that case.
            require(
                os.path.lexists(case / "container.json"),
                "root_create_requires_reconciliation",
            )
        self._kernel_scope(grant, empty=True)
        receipt = {"grant_sha256": sha(grant), "state": "absent"}
        if not os.path.lexists(case / "cleanup.json"):
            try:
                store(case / "cleanup.json", receipt)
            except FileExistsError:
                pass
        require(
            _decode(protected(case / "cleanup.json", 0o600)) == receipt,
            "root_cleanup_receipt_changed",
        )
        mounts = case / "mounts"
        if mounts.exists():
            for name in MOUNT_TARGETS:
                path = mounts / name
                path.unlink(missing_ok=True)
            try:
                mounts.rmdir()
            except FileNotFoundError:
                pass

    def observe(self, body):
        require(set(body) == {"grant", "worker"}, "root_observe_changed")
        grant = body["grant"]
        case = self._saved(grant)
        require(
            _decode(protected(case / "worker.json", 0o600)) == body["worker"],
            "root_worker_changed",
        )
        if os.path.lexists(case / "finished.json"):
            self._revoke_spending(grant)
            return _decode(protected(case / "finished.json", 0o600))
        with self.guard:
            if os.path.lexists(case / "stop.json") and os.path.lexists(
                case / "cleanup.json"
            ):
                self._kernel_scope(grant, empty=True)
                self._revoke_spending(grant)
                result = dict(
                    grant_sha256=sha(grant),
                    state="finished",
                    worker=body["worker"],
                    exit_code=137,
                    timed_out=time.time_ns() // 1000000 >= grant["expires_at_ms"],
                    overflow=False,
                )
                store(case / "finished.json", result)
                return result
            item = self._inspect(grant)
            try:
                self._current(grant)
            except Exception:
                self.revoke({"grant": grant})
                result = dict(
                    grant_sha256=sha(grant),
                    state="finished",
                    worker=body["worker"],
                    exit_code=137,
                    timed_out=time.time_ns() // 1000000 >= grant["expires_at_ms"],
                    overflow=False,
                )
            else:
                if item["State"]["Running"]:
                    require(
                        self._worker(grant, item) == body["worker"],
                        "root_worker_changed",
                    )
                    return dict(grant_sha256=sha(grant), state="running")
                result = dict(
                    grant_sha256=sha(grant),
                    state="finished",
                    worker=body["worker"],
                    exit_code=item["State"]["ExitCode"],
                    timed_out=item["State"]["ExitCode"] == 124,
                    overflow=item["State"]["ExitCode"] == 125,
                )
                self._cleanup(grant)
            self._revoke_spending(grant)
            store(case / "finished.json", result)
            return result

    def revoke(self, body):
        require(set(body) == {"grant"}, "root_revoke_changed")
        grant = body["grant"]
        case = self._saved(grant)
        if not os.path.lexists(case / "stop.json"):
            try:
                store(case / "stop.json", dict(grant_sha256=sha(grant)))
            except FileExistsError:
                pass
        try:
            self._cleanup(grant)
        finally:
            # Wallet or registry outage must never prevent the execution fence;
            # a daemon outage must never skip spending revocation either.
            self._revoke_spending(grant)
        return {"grant_sha256": sha(grant), "state": "stopped"}

    def _saved_scope(self, grant):
        case = self._saved(grant)
        value = _decode(protected(case / "owner-scope.json", 0o600))
        require(
            type(value) is dict
            and set(value) == {"grant_sha256", "scope_sha256"}
            and value["grant_sha256"] == sha(grant)
            and _digest(value["scope_sha256"]),
            "root_saved_scope_changed",
        )
        return value["scope_sha256"]

    def _revoke_spending(self, grant):
        scope = self._saved_scope(grant)
        case = self._saved(grant)
        receipt = {
            "grant_sha256": sha(grant),
            "scope_sha256": scope,
            "state": "revoked",
        }
        path = case / "owner-revoked.json"
        if not os.path.lexists(path):
            # Cleanup-only observers connect lazily, after the kernel fence.
            owner = getattr(self, "owner", None)
            if owner is None:
                owner = RootOwnerClient(
                    self.cfg["owner_socket"], self.cfg["owner_service_uid"]
                )
            require(owner.revoke(scope) is None, "root_owner_revocation_unknown")
            try:
                store(path, receipt)
            except FileExistsError:
                pass
        require(
            _decode(protected(path, 0o600)) == receipt,
            "root_owner_revocation_receipt_changed",
        )

    def reconcile(self, body):
        require(
            set(body) == {"attempt", "record", "recipe_sha256"}
            and body["recipe_sha256"] == sha(self.recipe),
            "root_reconcile_changed",
        )
        attempt = body["attempt"]
        case = self._case(attempt["attempt_id"])
        state = "unknown"
        if case.is_dir() and not os.path.lexists(case / "start-intent.json"):
            intent = _decode(protected(case / "prepare-intent.json", 0o600))
            if intent["attempt"] == attempt:
                state = "not_started"
        value = dict(
            attempt_id=attempt["attempt_id"], attempt_sha256=sha(attempt), state=state
        )
        return value | {"receipt_sha256": sha(value)}


def _ticks(pid):
    return int(
        (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()[19]
    )


def _owner_alive(pid, ticks):
    try:
        fields = (
            (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()
        )
        return fields[0] not in ("Z", "X") and int(fields[19]) == ticks
    except (OSError, ValueError, IndexError):
        return False


def watchdog(configuration, identity, owner_pid, owner_ticks):
    supervisor = RootSupervisor(configuration, cleanup_only=True)
    case = supervisor._case(identity)
    grant = _decode(protected(case / "grant.json", 0o600))
    failed_at = None
    while not os.path.lexists(case / "finished.json"):
        if failed_at is None:
            try:
                require(_owner_alive(owner_pid, owner_ticks), "root_owner_lost")
                supervisor._current(grant)
            except Exception:
                failed_at = time.monotonic()
        if failed_at is not None:
            try:
                supervisor.revoke({"grant": grant})
                return
            except Exception:
                # Cleanup retries cannot acquire another launch or inference root.
                # Persistent frozen/unknown state survives this bounded observer.
                if time.monotonic() - failed_at >= 30:
                    return
        time.sleep(0.05)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_POST(self):
        try:
            import struct

            peer_pid, uid, _ = struct.unpack(
                "3i",
                self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            )
            require(
                uid == self.server.backend.recipe["broker_uid"], "root_caller_denied"
            )
            method = self.path.removeprefix("/harness-launch/")
            require(
                self.path == "/harness-launch/" + method
                and method
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
                ),
                "root_method_denied",
            )
            if method == "gateway_peer_v1":
                require_broker_pid_namespace(peer_pid)
            lengths = self.headers.get_all("Content-Length", [])
            require(
                len(lengths) == 1
                and lengths[0].isascii()
                and lengths[0].isdecimal()
                and 0 < int(lengths[0]) <= 131072
                and self.headers.get("Transfer-Encoding") is None
                and self.headers.get("Content-Encoding") in (None, "identity"),
                "root_frame_changed",
            )
            raw = self.rfile.read(int(lengths[0]))
            require(len(raw) == int(lengths[0]), "root_frame_changed")
            value = getattr(self.server.backend, method)(_decode(raw))
            reply = canonical(value).encode()
            require(len(reply) <= 32768, "root_reply_overflow")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        except Exception:
            self.send_error(503, "protected launch unavailable")


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, backend):
        self.backend = backend
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(backend.cfg["socket_path"], Handler)
        os.chown(backend.cfg["socket_path"], 0, backend.recipe["broker_uid"])
        os.chmod(backend.cfg["socket_path"], 0o660)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "watchdog":
        watchdog(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    elif len(sys.argv) == 3 and sys.argv[1] == "serve":
        with Server(RootSupervisor(sys.argv[2])) as server:
            server.serve_forever()
    else:
        raise SystemExit("expected serve CONFIG or fixed watchdog arguments")
