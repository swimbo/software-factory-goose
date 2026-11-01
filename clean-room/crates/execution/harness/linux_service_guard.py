#!/usr/bin/env python3
"""One-use PID1-owned cleanup guard. This module grants no launch authority."""

import ctypes
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protected_goose_runtime import sha
from protected_spending_control import _decode


class GuardRefused(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise GuardRefused(reason)


def unit_name(grant):
    return "sfactoryguard" + sha(grant) + ".service"


def _unit(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"sfactoryguard[0-9a-f]{64}\.service", value),
        "guard_unit_changed",
    )
    return value


def _digest(value, length=64):
    return (
        isinstance(value, str)
        and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None
    )


def _group(value):
    require(
        isinstance(value, str)
        and value.startswith("/")
        and value != "/"
        and ".." not in value.split("/")
        and "\x00" not in value
        and "\n" not in value,
        "guard_cgroup_unavailable",
    )
    return value.rstrip("/")


def _separate(first, second):
    first, second = _group(first), _group(second)
    return (
        first != second
        and not first.startswith(second + "/")
        and not second.startswith(first + "/")
    )


def service_policy(argv, cleanup_argv, runtime_us):
    require(
        type(runtime_us) is int and 0 < runtime_us <= 215000000, "guard_runtime_changed"
    )
    for command in (argv, cleanup_argv):
        require(
            type(command) is list
            and 1 <= len(command) <= 16
            and command[0].startswith("/")
            and all(
                isinstance(v, str)
                and v
                and len(v.encode()) <= 4096
                and "\x00" not in v
                and "\n" not in v
                for v in command
            ),
            "guard_command_changed",
        )
    return [
        ("Description", "s", "Software factory bounded attempt cleanup"),
        ("Type", "s", "exec"),
        ("User", "s", "root"),
        ("Group", "s", "root"),
        ("Slice", "s", "system.slice"),
        ("Restart", "s", "no"),
        ("KillMode", "s", "control-group"),
        ("SendSIGKILL", "b", True),
        ("NoNewPrivileges", "b", True),
        ("PrivateNetwork", "b", True),
        ("RuntimeMaxUSec", "t", runtime_us),
        ("TimeoutStartUSec", "t", 5000000),
        ("TimeoutStopUSec", "t", 35000000),
        ("MemoryMax", "t", 268435456),
        ("TasksMax", "t", 32),
        ("CPUQuotaPerSecUSec", "t", 1000000),
        ("StandardInput", "s", "null"),
        ("StandardOutput", "s", "null"),
        ("StandardError", "s", "null"),
        ("ExecStart", "a(sasb)", argv),
        ("ExecStopPost", "a(sasb)", cleanup_argv),
    ]


def validate_ready(intent, ready, snapshot):
    extra = {"pid", "ticks", "invocation_id", "cgroup"}
    require(
        type(intent) is dict
        and set(intent)
        == {
            "schema",
            "grant_sha256",
            "config_sha256",
            "guard_sha256",
            "supervisor_sha256",
            "unit",
            "owner_pid",
            "owner_ticks",
            "owner_cgroup",
            "worker_cgroup",
            "boot_id",
        }
        and type(intent["schema"]) is int
        and intent["schema"] == 1
        and all(
            _digest(intent[k])
            for k in (
                "grant_sha256",
                "config_sha256",
                "guard_sha256",
                "supervisor_sha256",
            )
        )
        and type(intent["owner_pid"]) is int
        and intent["owner_pid"] > 1
        and type(intent["owner_ticks"]) is int
        and intent["owner_ticks"] > 0,
        "guard_intent_changed",
    )
    _unit(intent["unit"])
    require(
        type(intent) is dict
        and type(ready) is dict
        and set(ready) == set(intent) | extra
        and all(ready[k] == v for k, v in intent.items()),
        "guard_ready_binding_changed",
    )
    require(
        type(ready["pid"]) is int
        and ready["pid"] > 1
        and type(ready["ticks"]) is int
        and ready["ticks"] > 0
        and _digest(ready["invocation_id"], 32)
        and snapshot["Id"] == intent["unit"]
        and snapshot["ActiveState"] == "active"
        and snapshot["SubState"] == "running"
        and snapshot["MainPID"] == ready["pid"]
        and snapshot["InvocationID"] == ready["invocation_id"]
        and snapshot["ControlGroup"] == ready["cgroup"]
        and _separate(ready["cgroup"], intent["owner_cgroup"])
        and _separate(ready["cgroup"], intent["worker_cgroup"]),
        "guard_identity_changed",
    )
    return ready


def _immutable(path, expected, maximum=268435456):
    require(_digest(expected), "guard_source_digest_changed")
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "guard_source_path_changed")
    # Unlike a worker input, a library or executable will be reopened by PID1.
    # Every ancestor therefore remains outside unprivileged write authority.
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(
            info.st_uid == 0
            and not info.st_mode & 0o022
            and (
                stat.S_ISREG(info.st_mode)
                if parent == path
                else stat.S_ISDIR(info.st_mode)
            ),
            "guard_source_ownership_changed",
        )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(0 < info.st_size <= maximum, "guard_source_size_changed")
        digest = hashlib.sha256()
        while raw := os.read(fd, 65536):
            digest.update(raw)
        require(digest.hexdigest() == expected, "guard_source_changed")
    finally:
        os.close(fd)


class _Error(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("message", ctypes.c_char_p),
        ("need_free", ctypes.c_int),
    ]


class SystemdManager:
    """Typed, deadline-bounded calls to Root's actual PID1 private bus."""

    DEST = b"org.freedesktop.systemd1"
    PATH = b"/org/freedesktop/systemd1"
    MANAGER = b"org.freedesktop.systemd1.Manager"

    def __init__(self, library_path, library_sha256):
        require(sys.platform == "linux" and os.geteuid() == 0, "guard_root_required")
        _immutable(library_path, library_sha256)
        self.lib = ctypes.CDLL(str(library_path))
        self.bus = ctypes.c_void_p()
        self.deadline = time.monotonic() + 2.5
        p, s, i = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
        signatures = {
            "sd_bus_new": [ctypes.POINTER(p)],
            "sd_bus_unref": [p],
            "sd_bus_set_address": [p, s],
            "sd_bus_start": [p],
            "sd_bus_get_fd": [p],
            "sd_bus_set_method_call_timeout": [p, ctypes.c_uint64],
            "sd_bus_message_new_method_call": [p, ctypes.POINTER(p), s, s, s, s],
            "sd_bus_message_append_basic": [p, ctypes.c_char, p],
            "sd_bus_message_open_container": [p, ctypes.c_char, s],
            "sd_bus_message_close_container": [p],
            "sd_bus_message_unref": [p],
            "sd_bus_message_read_basic": [p, ctypes.c_char, p],
            "sd_bus_message_read_array": [
                p,
                ctypes.c_char,
                ctypes.POINTER(p),
                ctypes.POINTER(ctypes.c_size_t),
            ],
            "sd_bus_call": [
                p,
                p,
                ctypes.c_uint64,
                ctypes.POINTER(_Error),
                ctypes.POINTER(p),
            ],
            "sd_bus_get_property": [
                p,
                s,
                s,
                s,
                s,
                ctypes.POINTER(_Error),
                ctypes.POINTER(p),
                s,
            ],
            "sd_bus_error_free": [ctypes.POINTER(_Error)],
        }
        for name, args in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes = args
            function.restype = (
                p if name in ("sd_bus_unref", "sd_bus_message_unref") else i
            )
        try:
            self._ok(self.lib.sd_bus_new(ctypes.byref(self.bus)))
            self._ok(
                self.lib.sd_bus_set_address(self.bus, b"unix:path=/run/systemd/private")
            )
            self._ok(
                self.lib.sd_bus_set_method_call_timeout(self.bus, self._remaining())
            )
            self._ok(self.lib.sd_bus_start(self.bus))
            descriptor = self.lib.sd_bus_get_fd(self.bus)
            self._ok(descriptor)
            with socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                require(
                    struct.unpack(
                        "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    == (1, 0, 0),
                    "guard_pid1_peer_changed",
                )
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _ok(result):
        require(result >= 0, "guard_systemd_outcome_unknown")
        return result

    def _remaining(self):
        value = int((self.deadline - time.monotonic()) * 1000000)
        require(value > 0, "guard_systemd_deadline")
        return value

    def close(self):
        if self.bus:
            self.lib.sd_bus_unref(self.bus)
            self.bus = ctypes.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _basic(self, message, signature, value):
        if signature in ("s", "o"):
            keep = ctypes.c_char_p(value.encode())
        elif signature == "t":
            keep = ctypes.c_uint64(value)
        elif signature == "b":
            keep = ctypes.c_int(bool(value))
        else:
            raise GuardRefused("guard_type_changed")
        pointer = keep if signature in ("s", "o") else ctypes.byref(keep)
        self._ok(
            self.lib.sd_bus_message_append_basic(message, signature.encode(), pointer)
        )

    def _open(self, message, kind, signature):
        self._ok(
            self.lib.sd_bus_message_open_container(
                message, kind.encode(), signature.encode()
            )
        )

    def _end(self, message):
        self._ok(self.lib.sd_bus_message_close_container(message))

    def _properties(self, message, values):
        self._open(message, "a", "(sv)")
        for name, signature, value in values:
            self._open(message, "r", "sv")
            self._basic(message, "s", name)
            self._open(message, "v", signature)
            if signature == "a(sasb)":
                self._open(message, "a", "(sasb)")
                self._open(message, "r", "sasb")
                self._basic(message, "s", value[0])
                self._open(message, "a", "s")
                for argument in value:
                    self._basic(message, "s", argument)
                self._end(message)
                self._basic(message, "b", False)
                self._end(message)
                self._end(message)
            else:
                self._basic(message, signature, value)
            self._end(message)
            self._end(message)
        self._end(message)

    def _call(self, method, build):
        message, reply, error = ctypes.c_void_p(), ctypes.c_void_p(), _Error()
        try:
            self._ok(
                self.lib.sd_bus_message_new_method_call(
                    self.bus,
                    ctypes.byref(message),
                    self.DEST,
                    self.PATH,
                    self.MANAGER,
                    method.encode(),
                )
            )
            build(message)
            self._ok(
                self.lib.sd_bus_call(
                    self.bus,
                    message,
                    self._remaining(),
                    ctypes.byref(error),
                    ctypes.byref(reply),
                )
            )
            result = ctypes.c_char_p()
            self._ok(
                self.lib.sd_bus_message_read_basic(reply, b"o", ctypes.byref(result))
            )
            require(result.value is not None, "guard_systemd_empty_reply")
            return result.value.decode()
        finally:
            self.lib.sd_bus_error_free(ctypes.byref(error))
            self.lib.sd_bus_message_unref(reply)
            self.lib.sd_bus_message_unref(message)

    def start(self, unit, argv, cleanup_argv, runtime_us):
        _unit(unit)
        policy = service_policy(argv, cleanup_argv, runtime_us)

        def build(message):
            self._basic(message, "s", unit)
            self._basic(message, "s", "fail")
            self._properties(message, policy)
            self._open(message, "a", "(sa(sv))")
            self._end(message)

        return self._call("StartTransientUnit", build)

    def _property(self, path, interface, name, signature):
        reply, error = ctypes.c_void_p(), _Error()
        try:
            self._ok(
                self.lib.sd_bus_set_method_call_timeout(self.bus, self._remaining())
            )
            self._ok(
                self.lib.sd_bus_get_property(
                    self.bus,
                    self.DEST,
                    path.encode(),
                    interface.encode(),
                    name.encode(),
                    ctypes.byref(error),
                    ctypes.byref(reply),
                    signature.encode(),
                )
            )
            if signature == "ay":
                pointer, size = ctypes.c_void_p(), ctypes.c_size_t()
                self._ok(
                    self.lib.sd_bus_message_read_array(
                        reply, b"y", ctypes.byref(pointer), ctypes.byref(size)
                    )
                )
                require(size.value == 16, "guard_invocation_changed")
                return ctypes.string_at(pointer, size.value).hex()
            result = ctypes.c_char_p() if signature == "s" else ctypes.c_uint32()
            self._ok(
                self.lib.sd_bus_message_read_basic(
                    reply, signature.encode(), ctypes.byref(result)
                )
            )
            if signature == "s":
                require(
                    result.value is not None and len(result.value) <= 4096,
                    "guard_systemd_property_changed",
                )
                return result.value.decode()
            return result.value
        finally:
            self.lib.sd_bus_error_free(ctypes.byref(error))
            self.lib.sd_bus_message_unref(reply)

    def snapshot(self, unit):
        _unit(unit)
        path = self._call("GetUnit", lambda message: self._basic(message, "s", unit))
        result = {
            name: self._property(path, "org.freedesktop.systemd1.Unit", name, signature)
            for name, signature in (
                ("Id", "s"),
                ("ActiveState", "s"),
                ("SubState", "s"),
                ("InvocationID", "ay"),
            )
        }
        for name, signature in (("ControlGroup", "s"), ("MainPID", "u")):
            result[name] = self._property(
                path, "org.freedesktop.systemd1.Service", name, signature
            )
        return result


def _process_group(pid):
    lines = (Path("/proc") / str(pid) / "cgroup").read_text().strip().splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::"), "guard_cgroup_unavailable")
    return _group(lines[0][3:])


def _binding(supervisor):
    from linux_supervisor import protected

    cfg = supervisor.cfg
    require(
        cfg["schema"] == 2
        and cfg["guard_program"] == str(Path(__file__).resolve())
        and cfg["supervisor_program"]
        == str(Path(__file__).with_name("linux_supervisor.py").resolve()),
        "guard_source_install_changed",
    )
    for name in ("guard_program", "supervisor_program", "python", "systemd_library"):
        _immutable(cfg[name], cfg[name + "_sha256"])
    decoded = _decode(protected(supervisor.configuration, 0o600))
    require(decoded == cfg, "guard_configuration_changed")
    return {
        "config_sha256": sha(cfg),
        "guard_sha256": cfg["guard_program_sha256"],
        "supervisor_sha256": cfg["supervisor_program_sha256"],
    }


def _manager(supervisor):
    return SystemdManager(
        supervisor.cfg["systemd_library"], supervisor.cfg["systemd_library_sha256"]
    )


def start_guard(supervisor, grant):
    from linux_supervisor import store, _ticks

    case = supervisor._saved(grant)
    supervisor._saved_scope(grant)
    binding = _binding(supervisor)
    intent = dict(
        schema=1,
        grant_sha256=sha(grant),
        **binding,
        unit=unit_name(grant),
        owner_pid=os.getpid(),
        owner_ticks=_ticks(os.getpid()),
        owner_cgroup=_process_group(os.getpid()),
        worker_cgroup=grant["cgroup_path"].removeprefix("/sys/fs/cgroup"),
        boot_id=grant["boot_id"],
    )
    require(
        not os.path.lexists(case / "guard-intent.json"), "guard_start_already_attempted"
    )
    store(case / "guard-intent.json", intent)
    argv = [
        supervisor.cfg["python"],
        "-I",
        "-B",
        supervisor.cfg["guard_program"],
        "monitor",
        str(supervisor.configuration),
        grant["attempt_id"],
        binding["config_sha256"],
    ]
    cleanup = list(argv)
    cleanup[4] = "cleanup"
    runtime = (grant["expires_at_ms"] - time.time_ns() // 1000000) * 1000 + 35000000
    with _manager(supervisor) as manager:
        manager.start(intent["unit"], argv, cleanup, runtime)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if os.path.lexists(case / "guard-ready.json"):
            return check_guard(supervisor, grant)
        time.sleep(0.02)
    raise GuardRefused("guard_readiness_unknown")


def check_guard(supervisor, grant):
    from linux_supervisor import protected, _owner_alive

    case = supervisor._saved(grant)
    binding = _binding(supervisor)
    intent = _decode(protected(case / "guard-intent.json", 0o600))
    require(
        all(intent[k] == v for k, v in binding.items())
        and intent["unit"] == unit_name(grant)
        and intent["grant_sha256"] == sha(grant)
        and intent["boot_id"] == grant["boot_id"],
        "guard_intent_changed",
    )
    ready = _decode(protected(case / "guard-ready.json", 0o600))
    with _manager(supervisor) as manager:
        validate_ready(intent, ready, manager.snapshot(intent["unit"]))
    require(
        _owner_alive(ready["pid"], ready["ticks"])
        and _process_group(ready["pid"]) == ready["cgroup"],
        "guard_process_changed",
    )
    return ready


def run_guard(configuration, identity, expected_config, *, cleanup=False):
    from linux_supervisor import RootSupervisor, protected, store, _ticks, _owner_alive

    supervisor = RootSupervisor(configuration, cleanup_only=True)
    binding = _binding(supervisor)
    require(binding["config_sha256"] == expected_config, "guard_configuration_changed")
    case = supervisor._case(identity)
    grant = _decode(protected(case / "grant.json", 0o600))
    supervisor._saved_scope(grant)
    intent = _decode(protected(case / "guard-intent.json", 0o600))
    require(
        intent["unit"] == unit_name(grant)
        and intent["grant_sha256"] == sha(grant)
        and all(intent[k] == v for k, v in binding.items())
        and intent["boot_id"]
        == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "guard_intent_changed",
    )
    with _manager(supervisor) as manager:
        observed = manager.snapshot(intent["unit"])
    require(
        observed["InvocationID"] == os.environ.get("INVOCATION_ID")
        and observed["ControlGroup"] == _process_group(os.getpid())
        and _separate(observed["ControlGroup"], intent["owner_cgroup"])
        and _separate(observed["ControlGroup"], intent["worker_cgroup"]),
        "guard_service_identity_changed",
    )
    if cleanup:
        deadline = time.monotonic() + 30
        while True:
            try:
                supervisor.revoke({"grant": grant})
                return
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
    require(observed["MainPID"] == os.getpid(), "guard_main_pid_changed")
    supervisor._current(grant)
    ready = dict(
        intent,
        pid=os.getpid(),
        ticks=_ticks(os.getpid()),
        invocation_id=observed["InvocationID"],
        cgroup=observed["ControlGroup"],
    )
    validate_ready(intent, ready, observed)
    store(case / "guard-ready.json", ready)
    failed_at = None
    while not os.path.lexists(case / "finished.json"):
        if failed_at is None:
            try:
                require(
                    _binding(supervisor) == binding, "guard_runtime_sources_changed"
                )
                require(
                    _owner_alive(intent["owner_pid"], intent["owner_ticks"]),
                    "guard_owner_lost",
                )
                supervisor._current(grant)
            except Exception:
                failed_at = time.monotonic()
        if failed_at is not None:
            try:
                supervisor.revoke({"grant": grant})
                return
            except Exception:
                if time.monotonic() - failed_at >= 30:
                    raise
        time.sleep(0.05)


if __name__ == "__main__":
    require(
        len(sys.argv) == 5 and sys.argv[1] in ("monitor", "cleanup"),
        "guard_arguments_changed",
    )
    run_guard(sys.argv[2], sys.argv[3], sys.argv[4], cleanup=sys.argv[1] == "cleanup")
