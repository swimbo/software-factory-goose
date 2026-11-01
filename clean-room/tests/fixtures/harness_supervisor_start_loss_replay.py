#!/usr/bin/env python3
"""Fresh-resource actual RootSupervisor.start lost-ack component replay.

Requires a preprovisioned empty Root-only /var/lib/sfactory-harness/qualification-
<32hex> host directory, identically visible to this controller and Docker. Never
creates the production namespace or installs a service. Root/catalog initialization
and the registry gate are explicit fixtures; the watchdog uses the same fixture
initializer. Pinned Goose is mounted but never invoked by the public idle worker.
No wallet, provider, production admission or whole-service-group proof is claimed.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_supervisor_loss_replay as prior

product = prior.product


class StartFixtureSupervisor(prior.FixtureSupervisor):
    def __init__(self, configuration, *, cleanup_only=False):
        super().__init__(configuration, cleanup_only=True)
        self.gate = type(
            "FixtureGate", (), {"admission": staticmethod(contextlib.nullcontext)}
        )()
        self.start_requests = 0

    def _docker(self, *args, timeout=8):
        if args and args[0] == "start" and self.cfg.get("drop_start_ack"):
            assert len(args) == 2 and re.fullmatch(r"[0-9a-f]{64}", args[1])
            self.start_requests += 1
            case = self._case(self.cfg["attempt_id"])
            product.store(case / "start-dispatched.json", {"container_id": args[1]})
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(5)
            try:
                connection.connect("/run/docker.sock")
                connection.sendall(
                    (
                        "POST /containers/" + args[1] + "/start HTTP/1.1\r\n"
                        "Host: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
                deadline = time.monotonic() + 4
                while not json.loads(super()._docker("inspect", args[1]))[0]["State"][
                    "Running"
                ]:
                    assert time.monotonic() < deadline, "fixture start was not observed"
                    time.sleep(0.02)
            finally:
                connection.close()  # The real start response is never read.
            raise subprocess.TimeoutExpired(["fixture-start-ack-discarded"], timeout)
        return super()._docker(*args, timeout=timeout)


def require_fixture_root(path):
    assert path.is_absolute() and path == path.resolve()
    assert re.fullmatch(
        r"/var/lib/sfactory-harness/qualification-[0-9a-f]{32}", str(path)
    )
    info = path.lstat()
    assert info.st_uid == 0 and info.st_gid == 0 and info.st_mode & 0o777 == 0o700
    assert not list(path.iterdir()), "fixture directory must be fresh and empty"
    for parent in path.parents:
        info = parent.lstat()
        assert info.st_uid == 0 and info.st_mode & 0o022 == 0


def run(base, goose):
    assert sys.platform == "linux" and os.geteuid() == 0
    require_fixture_root(base)
    assert hashlib.sha256(goose.read_bytes()).hexdigest() == prior.LINUX_GOOSE_SHA256
    configuration, grant, case, mounts, group = prior.setup(
        base, "actual_start_lost_ack"
    )
    # setup's earlier cleanup-only case has not executed anything. Replace only
    # this fresh fixture's placeholder records with the actual start contract.
    (case / "start-intent.json").unlink()
    for name in product.MOUNT_TARGETS:
        (mounts / name).unlink()
    mounts.rmdir()
    config = json.loads(configuration.read_bytes())
    config.update(attempt_id=grant["attempt_id"], drop_start_ack=True, goose=str(goose))
    source = base / "idle-worker.py"
    worker = b"import subprocess,time\nsubprocess.Popen(['/usr/local/bin/python3','-I','-B','-c','import time;time.sleep(60)'])\ntime.sleep(60)\n"
    product.store(source, worker, 0o444)
    launcher = base / "fixture-watchdog"
    launcher_source = (
        "#!"
        + sys.executable
        + "\nimport sys\nsys.path.insert(0,"
        + repr(str(Path(__file__).parent))
        + ")\n"
        "import harness_supervisor_start_loss_replay as f\n"
        "assert len(sys.argv)==9 and sys.argv[1:3]==['-I','-B'] and sys.argv[4]=='watchdog'\n"
        "f.product.RootSupervisor=f.StartFixtureSupervisor\n"
        "f.product.watchdog(sys.argv[5],sys.argv[6],int(sys.argv[7]),int(sys.argv[8]))\n"
    ).encode()
    product.store(launcher, launcher_source, 0o555)
    config.update(
        python=str(launcher),
        worker_program=str(source),
        worker_program_sha256=hashlib.sha256(worker).hexdigest(),
    )
    configuration.unlink()
    product.store(configuration, config)
    body = dict(
        grant=grant,
        prompt="Public no-inference lost-ack fixture",
        declarations_sha256="7" * 64,
        worker_protocol="unix-json-v1",
    )
    product.store(
        Path(config["catalog_root"]) / (grant["attempt_id"] + ".launch.json"),
        dict(
            prompt_sha256=hashlib.sha256(body["prompt"].encode()).hexdigest(),
            declarations_sha256=body["declarations_sha256"],
            profile_sha256="d" * 64,
            max_output_tokens=1,
        ),
    )
    relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    relay.bind(grant["relay_path"])
    os.chown(grant["relay_path"], 2005, 2001)
    os.chmod(grant["relay_path"], 0o660)
    supervisor = StartFixtureSupervisor(configuration)
    container = "sfactory-harness-" + grant["attempt_id"][4:]
    tracked = {}
    try:
        try:
            supervisor.start(body)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("lost start acknowledgement returned success")
        intent = (case / "start-intent.json").read_bytes()
        assert json.loads(intent) == body and not (case / "worker.json").exists()
        item = supervisor._inspect(grant)
        pid = item["State"]["Pid"]
        assert item["State"]["Running"]
        tracked[pid] = prior.ticks(pid)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
            if children:
                tracked.update({int(p): prior.ticks(int(p)) for p in children})
                break
            time.sleep(0.02)
        assert len(tracked) >= 2, "public worker descendant not observed"
        # Reconstructed supervisor reads retained state, never an in-memory flag.
        fresh = StartFixtureSupervisor(configuration)
        try:
            fresh.start(body)
        except product.SupervisorRefused as error:
            assert str(error) == "root_start_already_attempted"
        else:
            raise AssertionError("a fresh supervisor rearmed unknown start")
        attempt = json.loads((case / "prepare-intent.json").read_bytes())["attempt"]
        receipt = fresh.reconcile(
            dict(attempt=attempt, record={}, recipe_sha256=product.sha(fresh.recipe))
        )
        assert receipt["state"] == "unknown"
        fresh.revoke({"grant": grant})
        assert json.loads((case / "execution-fenced.json").read_bytes()) == {
            "grant_sha256": product.sha(grant),
            "state": "execution_fenced",
        }
        assert json.loads((case / "cleanup.json").read_bytes()) == {
            "grant_sha256": product.sha(grant),
            "state": "absent",
        }
        assert (case / "start-intent.json").read_bytes() == intent
        assert (
            not mounts.exists() and (group / "cgroup.freeze").read_text().strip() == "1"
        )
        assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
        assert all(prior.ticks(pid) != ticks for pid, ticks in tracked.items())
        assert supervisor.start_requests == 1 and fresh.start_requests == 0
        assert (
            fresh.reconcile(
                dict(
                    attempt=attempt, record={}, recipe_sha256=product.sha(fresh.recipe)
                )
            )["state"]
            == "unknown"
        )
        return dict(
            schema=1,
            component_only=True,
            actual_start_entrypoint=True,
            start_response_never_read=True,
            start_requests=1,
            reconstructed_supervisor_rearm_denied=True,
            unknown_reconcile_retained=True,
            worker_and_descendants_gone=True,
            exact_execution_fence_and_cleanup=True,
            owned_container=container,
            owned_cgroup=group.name,
            product_source_sha256=hashlib.sha256(
                Path(product.__file__).read_bytes()
            ).hexdigest(),
            fixture_source_sha256=hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            production_constructor=False,
            fixture_registry_gate=True,
            fixture_watchdog_initializer=True,
            whole_service_group_loss_qualified=False,
            production_admission=False,
            paid_calls=0,
            live_attempts=0,
            candidate_enabled=False,
            passed=True,
        )
    finally:
        relay.close()
        # A create collision does not transfer ownership of the name. Strictly
        # inspect grant labels, image and containment before removing an exact ID.
        try:
            owned = supervisor._inspect(grant)
        except subprocess.CalledProcessError:
            owned = None  # Unknown/absent is not permission for name-only deletion.
        if owned is not None:
            ident = owned["Id"]
            assert re.fullmatch(r"[0-9a-f]{64}", ident), "invalid owned container ID"
            subprocess.run(
                [
                    "/fixturebin/docker",
                    "--host",
                    "unix:///run/docker.sock",
                    "rm",
                    "-f",
                    ident,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12,
                check=True,
            )
        prior.slice_unit("StopUnit", group.name)
        marker = case / "watchdog.json"
        if marker.exists():
            child = json.loads(marker.read_bytes())["pid"]
            try:
                # waitpid proves our direct unreaped child; pidfd makes signal
                # delivery immune to PID reuse. No process-name/group signal.
                done, _ = os.waitpid(child, os.WNOHANG)
                if not done:
                    fd = os.pidfd_open(child)
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    finally:
                        os.close(fd)
                    os.waitpid(child, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("--goose", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.base, args.goose), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
