#!/usr/bin/env python3
"""Public disposable native worker proof; not Root production admission or paid runs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/execution/harness"))
sys.path.insert(0, str(Path(__file__).parent))
from factory_harness import Broker, Profile, canonical  # noqa: E402
from protected_goose_runtime import BaselineSession, BoundedWorkspace, ModelRelay  # noqa: E402
from harness_session import CandidateSession  # noqa: E402
from linux_goose_runtime import LinuxWorkerRelay, LINUX_GOOSE_SHA256  # noqa: E402
from harness_linux_goose_replay import SyntheticControl  # noqa: E402
from benchmark_acceptance import evaluate  # noqa: E402
from container_evaluator import DockerEvaluator  # noqa: E402

from linux_worker_image import WORKER_IMAGE as IMAGE  # noqa: E402


def docker(*args, timeout=40):
    return subprocess.run(
        ["docker", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=True,
    )


def run(goose, host, variant):
    assert hashlib.sha256(goose.read_bytes()).hexdigest() == LINUX_GOOSE_SHA256
    assert (
        docker("image", "inspect", "--format", "{{.Id}}", IMAGE).stdout.decode().strip()
        == IMAGE
    )
    ident = None
    with tempfile.TemporaryDirectory(prefix="sfactory-generic-worker-") as temp:
        root = Path(temp)
        work = root / "authorized"
        work.mkdir(mode=0o700)
        gate = root / "gate"
        gate.mkdir(mode=0o711)
        control = SyntheticControl(variant)
        cancelled = threading.Event()
        deadline = time.monotonic() + 60
        workspace = BoundedWorkspace(work, lambda s: s)
        profile = Profile(
            "d" * 64,
            LINUX_GOOSE_SHA256,
            "fixture",
            "e" * 64,
            "fixture",
            workspace.tools(),
        )
        broker = Broker(profile, control.authorize, lambda s: s)
        session = (
            CandidateSession(
                host=host,
                broker=broker,
                artifact_root=root / "artifacts",
                attempt="fixture-" + variant,
                snapshot=workspace.snapshot,
                deadline=deadline,
                cancelled=cancelled,
            )
            if variant == "candidate"
            else BaselineSession(broker, workspace.snapshot, cancelled, deadline)
        )
        prompt = json.loads(
            (ROOT / "crates/execution/harness/frozen-suite.json").read_text()
        )["tasks"][8]["spec"]
        attempt = dict(
            goose_build=LINUX_GOOSE_SHA256,
            profile="d" * 64,
            model="fixture",
            route="e" * 64,
        )
        relay = ModelRelay(
            attempt, session, control, prompt, "unused", lambda s: s, deadline
        )
        server = LinuxWorkerRelay(
            gate / "relay.sock",
            worker_uid=2001,
            relay=relay,
            deadline=deadline,
            cancelled=cancelled,
        )
        os.chmod(gate / "relay.sock", 0o666)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        worker = (ROOT / "crates/execution/harness/linux_worker.py").read_bytes()
        (gate / "worker.py").write_bytes(worker)
        (gate / "prompt.txt").write_text(prompt)
        launch = dict(
            schema=1,
            purpose="sfactory-harness-linux-v1",
            worker_uid=2001,
            broker_uid=os.getuid(),
            goose_sha256=LINUX_GOOSE_SHA256,
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            declarations_sha256=hashlib.sha256(
                canonical(session.declarations()).encode()
            ).hexdigest(),
            max_output_tokens=16384,
            max_runtime_ms=45000,
        )
        (gate / "profile.json").write_text(canonical(launch))
        (gate / "goose-profile.json").write_text(
            canonical(
                dict(
                    schema=1,
                    profile="nuc-root-supervised-stdio-v1",
                    task_id="01K00000000000000000000001",
                    generation="01K00000000000000000000000",
                    recipe_sha256="c" * 64,
                    worker_uid=2001,
                )
            )
        )
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            "type=bind,src=" + str(gate) + ",dst=/owned",
            "--entrypoint",
            "/bin/sh",
            IMAGE,
            "-c",
            "chown 0:0 /owned/worker.py /owned/prompt.txt /owned/profile.json /owned/goose-profile.json; chmod 444 /owned/worker.py /owned/prompt.txt /owned/profile.json /owned/goose-profile.json",
        )
        name = "sfactory-generic-proof-" + uuid.uuid4().hex
        args = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            "sfactory.generic.fixture=" + name,
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
            "--tmpfs",
            "/work:rw,nosuid,nodev,noexec,size=8m,nr_inodes=512,uid=2001,gid=2001,mode=0700",
            "--entrypoint",
            "/usr/local/bin/python3",
        ]
        for source, target in (
            (goose, "/goose"),
            (gate / "worker.py", "/factory/linux_worker.py"),
            (gate / "profile.json", "/factory/profile.json"),
            (gate / "goose-profile.json", "/run/software-factory-goose/profile.json"),
            (gate / "prompt.txt", "/factory/prompt.txt"),
            (gate / "relay.sock", "/gate/relay.sock"),
        ):
            args += [
                "--mount",
                "type=bind,src=" + str(source) + ",dst=" + target + ",readonly",
            ]
        args += [IMAGE, "-I", "-B", "/factory/linux_worker.py"]
        try:
            ident = docker(*args).stdout.decode().strip()
            assert len(ident) == 64
            snapshot = json.loads(docker("inspect", ident).stdout)[0]
            assert (
                snapshot["HostConfig"]["NetworkMode"] == "none"
                and snapshot["HostConfig"]["ReadonlyRootfs"]
            )
            assert {
                m["Destination"] for m in snapshot["Mounts"] if m["Type"] == "bind"
            } == {
                "/goose",
                "/factory/linux_worker.py",
                "/factory/profile.json",
                "/run/software-factory-goose/profile.json",
                "/factory/prompt.txt",
                "/gate/relay.sock",
            }
            try:
                result = docker("start", "--attach", ident, timeout=60)
            except subprocess.CalledProcessError as error:
                print(
                    canonical(
                        {
                            "fixture_failure": True,
                            "variant": variant,
                            "exit_code": error.returncode,
                            "worker_message": error.stderr.decode("utf-8", "replace")[
                                :1024
                            ],
                            "relay_failure": relay.failure_reason,
                            "synthetic_sends": len(control.sends),
                            "authorized_tools": len(control.authorizations),
                        }
                    ),
                    flush=True,
                )
                raise
            snapshot = json.loads(docker("inspect", ident).stdout)[0]
            assert snapshot["State"]["ExitCode"] == 0, (
                result.stdout.decode(),
                result.stderr.decode(),
                relay.failure_reason,
            )
            assert len(control.sends) == len(control.steps) + 1 and not relay.failed
            accepted = evaluate(
                "intervals",
                workspace.snapshot(),
                DockerEvaluator(work, root / "evaluation"),
            )
            assert accepted["accepted"] and accepted["independent"]
            return dict(
                variant=variant,
                synthetic_sends=len(control.sends),
                authorized_tools=len(control.authorizations),
                independent_accepted=True,
                worker_program_sha256=hashlib.sha256(worker).hexdigest(),
                no_harness_or_evaluator_mount=True,
                paid_calls=0,
                live_attempts=0,
                candidate_enabled=False,
            )
        finally:
            cancelled.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            workspace.close()
            if variant == "candidate":
                session.artifacts.close()
            if ident is not None:
                observed = json.loads(docker("inspect", ident).stdout)[0]
                assert (
                    observed["Config"]["Labels"]["sfactory.generic.fixture"] == name
                    and observed["Image"] == IMAGE
                )
                docker("rm", "-f", ident)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--goose", type=Path, required=True)
    p.add_argument("--host", type=Path, required=True)
    p.add_argument("--summary", type=Path, required=True)
    a = p.parse_args()
    result = dict(
        status="native_worker_component_only",
        variants=[run(a.goose, a.host, v) for v in ("baseline", "candidate")],
        root_supervisor_admission_verified=False,
        paid_calls=0,
        live_attempts=0,
        candidate_enabled=False,
    )
    fd = os.open(a.summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(result, out, indent=2)
    print(json.dumps(result))
