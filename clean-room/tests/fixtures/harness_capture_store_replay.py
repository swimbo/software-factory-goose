#!/usr/bin/env python3
"""Disposable kernel-role/SQLite capture proof, not wallet/launch authority.

Root fixture needs CHOWN, DAC_OVERRIDE, KILL, SETUID, SETGID, SYS_CHROOT only. Its fresh
ext-family rootfs contains public Python runtime/code. It creates no production
path, provider credential or spending allowance. The open operation is supplied
by a fixture broker, so a real wallet acquisition is explicitly not certified.
"""

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys

BASE = Path(sys.argv[1]) / "rootfs"
CODE = Path(__file__).resolve().parents[2] / "crates/execution/harness"
SOCK = "/var/lib/sfactory-harness/capture/socket/service.sock"
STATE = "/var/lib/sfactory-harness/capture/state"


def jail(uid):
    os.chroot(BASE)
    os.chdir("/")
    os.setgroups([] if uid == 2001 else [3003])
    os.setgid(uid)
    os.setuid(uid)
    sys.path.insert(0, "/code")


def data():
    from test_physical_usage import fixture
    from usage_rating import TariffCard, TariffRate

    binding, profile, envelope = fixture()
    card = TariffCard(
        "1",
        "constant_peak",
        "https://example.org/pricing",
        "b" * 64,
        1,
        1,
        100000,
        (
            TariffRate(
                "provider",
                "model",
                "0.0000001",
                "0.0000001",
                "0.0000001",
                "0.0000002",
                "0",
            ),
        ),
    )
    binding = replace(binding, tariff_sha256=card.sha256())
    envelope["binding"] = binding.as_dict()
    return binding, profile, envelope, card


def start():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            jail(2008)
            from gateway_custody import ProtectedCaptureStore, PrivateCustodyServer

            binding, profile, _, card = data()
            store = ProtectedCaptureStore(
                STATE + "/capture.db",
                service_uid=2008,
                owner="owner",
                route_sha256=binding.route_sha256,
                tariff=card,
                profiles=(profile,),
                components=("answer", "fallback"),
                broker_uid=2005,
                gateway_uid=2007,
                collector_uid=2006,
            )
            server = PrivateCustodyServer(
                SOCK, store, service_uid=2008, socket_gid=3003, prefix="/capture/"
            )
            os.write(w, b"1")
            os.close(w)
            server.serve_forever(poll_interval=0.1)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(w)
    assert os.read(r, 1) == b"1", "capture service failed startup"
    os.close(r)
    return pid


def actor(uid, method):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            jail(uid)
            from gateway_custody import PrivateCaptureOpenClient, root_binding
            from physical_usage import (
                PrivateCaptureClient,
                normalize_capture,
                payload_sha256,
            )
            from protected_spending_control import PrivateSpendingClient, ControlRefused
            from usage_rating import UsageRatedCollector

            binding, profile, envelope, card = data()
            if method == "worker":
                connection = socket.socket(socket.AF_UNIX)
                try:
                    connection.connect(SOCK)
                except PermissionError:
                    result = {"worker_denied_before_http": True}
                else:
                    raise AssertionError("worker connected")
                finally:
                    connection.close()
            elif method == "open":
                client = PrivateCaptureOpenClient(
                    SOCK, service_uid=2008, broker_uid=2005, owner="owner"
                )
                result = client.open(root_binding(binding.as_dict()))
                assert result["opened"] is True
            elif method == "close":
                client = PrivateSpendingClient(
                    SOCK, service_uid=2008, broker_uid=2007, owner="owner"
                )
                result = client._send(
                    "close",
                    json.dumps(
                        envelope, sort_keys=True, separators=(",", ":")
                    ).encode(),
                    prefix="/capture/",
                )
                assert result == {
                    "physical_manifest_sha256": binding.physical_manifest_sha256,
                    "stored": True,
                }
            else:
                client = PrivateCaptureClient(
                    SOCK,
                    service_uid=2008,
                    collector_uid=2006,
                    broker_uid=2005,
                    worker_uid=2001,
                    owner="owner",
                )
                assert client.closed(binding) == envelope
                manifest, usages, _, _ = normalize_capture(
                    envelope, binding, (profile,), ("answer", "fallback")
                )
                report = UsageRatedCollector(
                    card, card.sha256(), lambda c: usages[c.call_id]
                ).collect(manifest)
                assert report["usage_rated_microusd"] == 2
                report["capture_sha256"] = binding.physical_manifest_sha256
                report["usage_schema_profiles"] = [profile.as_dict()]
                report.pop("audit_sha256")
                report["audit_sha256"] = payload_sha256(report)
                invalid = copy.deepcopy(report)
                invalid["secret"] = "fixture-only-never-persist"
                invalid.pop("audit_sha256")
                invalid["audit_sha256"] = payload_sha256(invalid)
                try:
                    client.persist_audit(binding, invalid)
                except ControlRefused:
                    pass
                else:
                    raise AssertionError("unsanitized audit accepted")
                client.persist_audit(binding, report)
                result = {
                    "closed_verified": True,
                    "audit_persisted": True,
                    "rated_microusd": 2,
                    "invalid_audit_denied": True,
                }
            os.write(w, json.dumps(result).encode())
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(w)
    result = os.read(r, 65536)
    os.close(r)
    assert os.waitpid(pid, 0)[1] == 0, method
    return json.loads(result)


def stop(pid):
    alive, _ = os.waitpid(pid, os.WNOHANG)
    if not alive:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def negative_state_controls():
    """Root mutates only fresh fixture paths; actual service UID must refuse."""
    cases = (
        "writable_ancestor",
        "state_mode",
        "foreign_state_owner",
        "database_mode",
        "database_owner",
        "database_hardlink",
        "database_symlink",
        "state_acl",
        "fixture_backend",
    )
    results = []
    for name in cases:
        state = BASE / STATE.lstrip("/")
        database = state / "negative.db"
        original = state / "alias-target"
        ancestor = BASE / "var/lib/sfactory-harness"
        if name.startswith("database_"):
            database.write_bytes(b"")
            os.chmod(database, 0o600)
            os.chown(database, 2008, 2008)
        if name == "writable_ancestor":
            os.chmod(ancestor, 0o777)
        elif name == "state_mode":
            os.chown(state, 0, 0)
            os.chmod(state, 0o750)
            os.chown(state, 2008, 2008)
        elif name == "foreign_state_owner":
            os.chown(state, 2007, 2007)
        elif name == "database_mode":
            os.chown(database, 0, 0)
            os.chmod(database, 0o644)
            os.chown(database, 2008, 2008)
        elif name == "database_owner":
            os.chown(database, 2007, 2007)
        elif name == "database_hardlink":
            os.link(database, original)
        elif name == "database_symlink":
            database.rename(original)
            database.symlink_to("alias-target")
        elif name == "state_acl":
            import struct

            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", tag, perm, uid)
                for tag, perm, uid in (
                    (1, 7, 0xFFFFFFFF),
                    (2, 0, 2006),
                    (4, 0, 0xFFFFFFFF),
                    (16, 0, 0xFFFFFFFF),
                    (32, 0, 0xFFFFFFFF),
                )
            )
            os.chown(state, 0, 0)
            os.setxattr(state, "system.posix_acl_access", acl)
            os.chown(state, 2008, 2008)
            assert os.getxattr(state, "system.posix_acl_access") == acl
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(r)
                jail(2008)
                from gateway_custody import (
                    CaptureStore,
                    ProtectedCaptureStore,
                    PrivateCustodyServer,
                )

                binding, profile, _, card = data()
                policy = dict(
                    owner="owner",
                    route_sha256=binding.route_sha256,
                    tariff=card,
                    profiles=(profile,),
                    components=("answer", "fallback"),
                    broker_uid=2005,
                    gateway_uid=2007,
                    collector_uid=2006,
                )
                try:
                    if name == "fixture_backend":
                        with CaptureStore(STATE + "/negative.db", **policy) as pure:
                            PrivateCustodyServer(
                                str(Path(SOCK).parent / "negative.sock"),
                                pure,
                                service_uid=2008,
                                socket_gid=3003,
                                prefix="/capture/",
                            )
                    else:
                        ProtectedCaptureStore(
                            STATE + "/negative.db", service_uid=2008, **policy
                        )
                except Exception as error:
                    from protected_spending_control import ControlRefused

                    # An unrelated startup error cannot count as the intended refusal.
                    if name == "foreign_state_owner":
                        import errno

                        assert (
                            isinstance(error, PermissionError)
                            and error.errno == errno.EACCES
                        )
                        reason = "kernel_state_access_denied"
                    else:
                        assert isinstance(error, ControlRefused), type(error).__name__
                        assert str(error) in (
                            "capture_private_state_invalid",
                            "private_spending_acl_denied",
                            "custody_backend_invalid",
                        ), str(error)
                        reason = str(error)
                    os.write(
                        w,
                        json.dumps(
                            {"case": name, "denied": True, "reason": reason}
                        ).encode(),
                    )
                    os._exit(0)
                raise AssertionError("unsafe custody state accepted")
            except BaseException:
                import traceback

                traceback.print_exc()
                os._exit(1)
        os.close(w)
        raw = os.read(r, 65536)
        os.close(r)
        try:
            assert os.waitpid(pid, 0)[1] == 0, name
            results.append(json.loads(raw))
            assert not (
                BASE / str(Path(SOCK).parent / "negative.sock").lstrip("/")
            ).exists()
            if name not in ("fixture_backend",) and not name.startswith("database_"):
                assert not database.exists(), "refusal wrote database"
        finally:
            os.chown(state, 0, 0)
            if name == "state_acl":
                os.removexattr(state, "system.posix_acl_access")
            os.chmod(ancestor, 0o755)
            os.chmod(state, 0o700)
            os.chown(state, 2008, 2008)
            for path in (
                database,
                original,
                Path(str(database) + "-wal"),
                Path(str(database) + "-shm"),
            ):
                if os.path.lexists(path):
                    path.unlink()
    return results


def main():
    assert os.geteuid() == 0 and not BASE.exists()
    BASE.mkdir(mode=0o755)
    for directory in ("usr/local", "usr/lib"):
        shutil.copytree("/" + directory, BASE / directory, symlinks=True)
    for directory in ("lib", "lib64"):
        source = Path("/") / directory
        if source.is_symlink():
            (BASE / directory).symlink_to(os.readlink(source))
        elif source.exists():
            shutil.copytree(source, BASE / directory, symlinks=True)
    shutil.copytree(CODE, BASE / "code", ignore=shutil.ignore_patterns("__pycache__"))
    for part in (
        "var",
        "var/lib",
        "var/lib/sfactory-harness",
        "var/lib/sfactory-harness/capture",
    ):
        (BASE / part).mkdir(mode=0o755, exist_ok=True)
    for name, mode, group in (
        (STATE, 0o700, 2008),
        (str(Path(SOCK).parent), 0o750, 3003),
    ):
        path = BASE / name.lstrip("/")
        path.mkdir(mode=mode)
        os.chown(path, 2008, group)
    negative_results = negative_state_controls()
    pid = start()
    try:
        results = [
            actor(2001, "worker"),
            actor(2005, "open"),
            actor(2007, "close"),
            actor(2006, "audit"),
        ]
    finally:
        stop(pid)
    (BASE / SOCK.lstrip("/")).unlink()  # Root reconciles exact dead fixture listener.
    pid = start()
    try:
        results.append(actor(2006, "after_restart"))
    finally:
        stop(pid)
    print(
        json.dumps(
            {
                "schema": 1,
                "component": "actual_private_capture_roles_and_sqlite_restart",
                "results": results,
                "negative_state_controls": negative_results,
                "real_wallet_acquisition": False,
                "production_admission": False,
                "paid_calls": 0,
                "live_attempts": 0,
                "candidate_enabled": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
