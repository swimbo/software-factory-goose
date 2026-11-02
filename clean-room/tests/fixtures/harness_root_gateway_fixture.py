"""Root gateway lifecycle helpers for public disposable guard rehearsals only."""

import hashlib
import os
from pathlib import Path
import time
import json

import linux_supervisor as product

MARKER = "SFACTORY_PID1_GUARD_DISPOSABLE"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def launch_root_gateway(backend, grant, target):
    """The pinned public target listens only after its holding child is ready."""
    program = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        process, launched = backend._launch_gateway(grant, program)
    finally:
        os.close(program)
    deadline = time.monotonic() + 5
    path = "/var/lib/sfactory-harness/gw/" + grant["attempt_id"][4:] + ".sock"
    while True:
        assert process.poll() is None, "Root-launched gateway exited"
        executable = Path(f"/proc/{process.pid}/exe")
        lines = Path(f"/proc/{process.pid}/net/unix").read_text().splitlines()[1:]
        if digest(executable) == backend.cfg["gateway_executable_sha256"] and any(
            len(fields := line.split()) == 8
            and fields[7] == path
            and int(fields[3], 16) & 0x10000
            for line in lines
        ):
            break
        assert time.monotonic() < deadline, "Root gateway readiness unknown"
        time.sleep(0.01)
    return process, launched


def live_gateway_family(group, child):
    family = [
        {"pid": int(pid), "ticks": product._ticks(int(pid))}
        for pid in (group / "gateway/cgroup.procs").read_text().split()
    ]
    assert (
        len(family) >= 2
        and {"pid": child["pid"], "ticks": child["ticks"]} in family
        and all(product._owner_alive(p["pid"], p["ticks"]) for p in family)
    )
    return family


def retire_root_gateway_fixture(configuration, grant, group, child, slice_unit):
    """Retire only this public no-provider fixture; never issue Root cleanup proof."""
    base = configuration.parents[1]
    assert str(base).startswith("/var/lib/sfactory-harness/qualification-")
    assert (base / MARKER).read_text() == MARKER + "\n"
    backend = product.RootSupervisor(configuration, cleanup_only=True)
    case = backend._saved(grant)
    assert not product._owner_alive(child["pid"], child["ticks"])
    assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
    assert (group / "cgroup.freeze").read_text().strip() == "1"
    assert (case / "owner-revoked.json").exists()
    bound = json.loads(product.protected(case / "gateway-bound.json", 0o600))
    assert bound == json.loads(product.protected(case / "gateway-created.json", 0o600))
    with product.gateway_socket_parent(grant["attempt_id"]) as (fd, name, path):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        assert (path, info.st_dev, info.st_ino) == (
            bound["socket"]["path"],
            bound["socket"]["dev"],
            bound["socket"]["ino"],
        )
        os.unlink(name, dir_fd=fd)
        os.fsync(fd)
    leaf = json.loads(product.protected(case / "gateway-leaf-created.json", 0o600))
    product.remove_fenced_gateway_leaf(grant, leaf["leaf"])
    item = backend._inspect(grant)
    assert not item["State"]["Running"]
    backend._docker("rm", "-f", item["Id"])
    slice_unit("StopUnit", group.name)
    deadline = time.monotonic() + 3
    while group.exists():
        assert time.monotonic() < deadline, "fixture slice retirement unknown"
        time.sleep(0.01)
    assert not (case / "cleanup.json").exists()
    product.store(
        case / "fixture-retired.json",
        {"grant_sha256": product.sha(grant), "production_cleanup_qualified": False},
    )
