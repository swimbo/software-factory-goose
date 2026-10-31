# ruff: noqa: E402
#!/usr/bin/env python3
"""Run on Linux from a fresh source-only stage. Synthetic inference, no activation.

Requires the existing pinned public Goose binary and cached worker image. Creates
only uniquely named disposable containers and a fresh owned temporary directory.
"""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/execution/harness"))
from factory_harness import Broker, Profile, canonical
from protected_goose_runtime import BoundedWorkspace, BaselineSession, ModelRelay
from linux_goose_runtime import LinuxWorkerRelay, LINUX_GOOSE_SHA256

IMAGE = "sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a"
GOOSE = Path("/usr/local/libexec/software-factory-goose/goose-protected-802d1478")


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=70,
        **kwargs,
    )


SOLUTION = "import json,sys\ndef merge_intervals(items):\n    out=[]\n    for a,b in sorted(items):\n        if a>b: raise ValueError()\n        if out and a<=out[-1][1]: out[-1][1]=max(b,out[-1][1])\n        else: out.append([a,b])\n    return out\nif __name__=='__main__':\n    for line in sys.stdin:\n        try: result={'result':merge_intervals(json.loads(line)['intervals'])}\n        except Exception: result={'error':'invalid'}\n        print(json.dumps(result))\n"
FILES = {
    "solution.py": SOLUTION,
    "README.md": "Run python3 -I -B test_solution.py.\n",
    "test_solution.py": "import solution\nassert solution.merge_intervals([[2,3],[1,2]])==[[1,3]]\n",
}


class SyntheticControl:
    def __init__(self, variant):
        self.sends = []
        self.authorizations = []
        writes = [
            ("write_file", {"path": name, "content": content})
            for name, content in FILES.items()
        ]
        self.steps = (
            [("list_files", {})] + writes + [("read_file", {"path": "solution.py"})]
            if variant == "baseline"
            else [
                ("fetch_tool_schema", {"name": "write_file"}),
                (
                    "run_script",
                    {
                        "script": ";".join(
                            'await tools.call("write_file",' + canonical(args) + ")"
                            for _, args in writes
                        )
                        + '; return "files ready";'
                    },
                ),
            ]
        )

    def authorize(self, name, args):
        self.authorizations.append((name, args))
        return True

    def exchange(self, attempt, body, sequence):
        self.sends.append(body)
        if sequence < len(self.steps):
            name, args = self.steps[sequence]
            delta = {
                "role": "assistant",
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "fixture-tool-" + str(sequence),
                        "type": "function",
                        "function": {
                            "name": "factory__" + name,
                            "arguments": canonical(args),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        else:
            delta = {"content": "SYNTHETIC_DONE"}
            finish = "stop"
        events = [
            {
                "model": "auto",
                "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
            },
            {
                "model": "auto",
                "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
            },
        ]
        return {
            "sse": (
                "".join("data: " + canonical(e) + "\n\n" for e in events)
                + "data: [DONE]\n\n"
            ).encode(),
            "call_id": "synthetic-" + str(sequence),
            "physical_manifest_sha256": "a" * 64,
            "billing_receipt_sha256": "b" * 64,
            "billed_microusd": 0,
        }


def main():
    variant = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    assert variant in ("baseline", "candidate")
    assert sys.platform == "linux"
    assert hashlib.sha256(GOOSE.read_bytes()).hexdigest() == LINUX_GOOSE_SHA256
    token = uuid.uuid4().hex
    names = []
    guardian = None
    with tempfile.TemporaryDirectory(prefix="sfactory-linux-goose-") as temp:
        root = Path(temp)
        gate = root / "gate"
        gate.mkdir(mode=0o711)
        work = root / "authorized"
        work.mkdir(mode=0o700)
        control = SyntheticControl(variant)
        cancelled = threading.Event()
        deadline = time.monotonic() + 60
        workspace = BoundedWorkspace(work, lambda s: s)

        def write(args):
            for name, content in args["files"].items():
                workspace.write({"path": name, "content": content})
            return "Files written."

        worker = (
            (ROOT / "deployment/relay/nuc_goose_worker.py")
            .read_text()
            .replace(
                "'GOOSE_MODEL':'gpt-4o-mini'",
                "'GOOSE_MODEL':'auto','GOOSE_MAX_TOKENS':'16384'",
            )
        )
        start = worker.index("def mcp():")
        end = worker.index("def protected_prompt():")
        worker = worker.replace("'--max-turns','3'", "'--max-turns','12'")
        worker = (
            worker[:start]
            + "def mcp():\n    sys.path.insert(0,'/harness')\n    from harness_mcp import serve\n    from linux_goose_runtime import LinuxSessionClient\n    serve(LinuxSessionClient('/gate/relay.sock',"
            + str(os.getuid())
            + "))\n    return 0\n\n"
            + worker[end:]
        )
        (gate / "worker.py").write_text(worker)
        (gate / "worker.py").chmod(0o444)
        # Docker's private root helper owns only these fresh fixture files.
        profile = {
            "schema": 1,
            "profile": "nuc-root-supervised-stdio-v1",
            "task_id": "01K00000000000000000000001",
            "generation": "01K00000000000000000000000",
            "recipe_sha256": "c" * 64,
            "worker_uid": 2001,
        }
        (gate / "profile.json").write_text(canonical(profile))
        (gate / "prompt.txt").write_text(
            json.loads(
                (ROOT / "crates/execution/harness/frozen-suite.json").read_text()
            )["tasks"][8]["spec"]
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
            "chown 0:0 /owned/profile.json /owned/prompt.txt; chmod 444 /owned/profile.json /owned/prompt.txt",
        )
        profile_obj = Profile(
            "d" * 64,
            LINUX_GOOSE_SHA256,
            "fixture",
            "e" * 64,
            "fixture",
            workspace.tools(),
        )
        broker = Broker(profile_obj, control.authorize, lambda s: s)
        if variant == "candidate":
            from harness_session import CandidateSession

            session = CandidateSession(
                host=ROOT.parent / "script-host",
                broker=broker,
                artifact_root=root / "artifacts",
                attempt="fixture-" + token,
                snapshot=workspace.snapshot,
                deadline=deadline,
                cancelled=cancelled,
            )
        else:
            session = BaselineSession(broker, workspace.snapshot, cancelled, deadline)
        attempt = {
            "goose_build": LINUX_GOOSE_SHA256,
            "profile": "d" * 64,
            "model": "fixture",
            "route": "e" * 64,
        }
        relay = ModelRelay(
            attempt,
            session,
            control,
            (gate / "prompt.txt").read_text(),
            "unused",
            lambda s: s,
            deadline,
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
        common = [
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "1g",
            "--cpus",
            "1",
            "--user",
            "2001:2001",
            "--mount",
            "type=bind,src=" + str(gate) + ",dst=/gate,readonly",
            "--mount",
            "type=bind,src=" + str(GOOSE) + ",dst=/goose,readonly",
            "--mount",
            "type=bind,src="
            + str(ROOT / "crates/execution/harness")
            + ",dst=/harness,readonly",
        ]
        try:
            name = "sfactory-replay-" + token
            names.append(name)
            args = [
                "create",
                "--name",
                name,
                *common,
                "--tmpfs",
                "/work:rw,size=67108864,uid=2001,gid=2001,mode=0700",
                "--mount",
                "type=bind,src="
                + str(gate / "worker.py")
                + ",dst=/factory/nuc_goose_worker.py,readonly",
                "--mount",
                "type=bind,src="
                + str(gate / "profile.json")
                + ",dst=/run/software-factory-goose/profile.json,readonly",
                "--mount",
                "type=bind,src="
                + str(gate / "prompt.txt")
                + ",dst=/factory/prompt.txt,readonly",
                IMAGE,
            ]
            ident = docker(*args).stdout.decode().strip()
            guardian = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "import select,subprocess,sys; select.select([sys.stdin.buffer],[],[],65); subprocess.run(['docker','rm','-f',sys.argv[1]],check=True,stdout=subprocess.DEVNULL)",
                    ident,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            obj = json.loads(docker("inspect", ident).stdout)[0]
            assert (
                obj["Id"] == ident
                and obj["HostConfig"]["NetworkMode"] == "none"
                and obj["HostConfig"]["ReadonlyRootfs"]
            )
            try:
                result = docker("start", "-a", ident)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(
                    "synthetic worker failed: "
                    + error.stderr.decode()
                    + " relay="
                    + str(relay.failure_reason)
                ) from None
            assert b'"goose_exit":0' in result.stdout, result.stderr.decode()
            assert len(control.sends) == len(control.steps) + 1 and len(
                control.authorizations
            ) == (5 if variant == "baseline" else 3), (
                relay.failure_reason,
                control.authorizations,
            )
            assert "def merge_intervals" in (work / "solution.py").read_text()
            # Forged JSON role never substitutes for observed kernel UID.
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(str(gate / "relay.sock"))
                s.sendall(b'{"type":"inference","body":{},"uid":2001}\n')
                assert json.loads(s.recv(4096))["ok"] is False
            assert len(control.sends) == len(control.steps) + 1
            # Actual network/filesystem/process protection probes in a separate
            # UID2001 container with identical containment and no broker key.
            probe = "import os,socket,errno; s=socket.socket(); s.settimeout(.2); assert s.connect_ex(('198.51.100.1',443)) in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES); assert not os.path.exists('/var/lib/software-factory-goose'); assert not os.path.exists('/authorized'); assert not os.path.exists('/run/docker.sock'); exec(\"try:\\n open('/harness/linux_goose_runtime.py','w'); raise AssertionError('write allowed')\\nexcept OSError: pass\"); assert os.getuid()==2001; print('DENIALS_OK')"
            proof = docker(
                "run",
                "--rm",
                *common,
                "--entrypoint",
                "/usr/local/bin/python3",
                IMAGE,
                "-I",
                "-B",
                "-c",
                probe,
            )
            assert b"DENIALS_OK" in proof.stdout
            # An independent host process holds only an exact disposable ID.
            # It removes that container at its own monotonic deadline even if
            # this fixture owner disappears. This is rehearsal, not root launch.
            held = "sfactory-replay-held-" + token
            names.append(held)
            owner_args = [
                "create",
                "--name",
                held,
                *common,
                "--entrypoint",
                "/usr/local/bin/python3",
                IMAGE,
                "-I",
                "-B",
                "-c",
                "import os,time; p=os.fork(); os.setsid() if p==0 else None; print('DESCENDANT_ACTIVE',flush=True); time.sleep(90)",
            ]
            owner = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "import json,subprocess,sys,time; ident=subprocess.check_output(['docker',*json.loads(sys.argv[1])],text=True).strip(); subprocess.run(['docker','start',ident],check=True,stdout=subprocess.DEVNULL); print(ident,flush=True); time.sleep(90)",
                    json.dumps(owner_args),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            held_id = owner.stdout.readline().decode().strip()
            assert len(held_id) == 64
            observed = json.loads(docker("inspect", held_id).stdout)[0]
            assert observed["State"]["Running"] and observed["State"]["Pid"] > 1
            watchdog = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "import subprocess,sys,time; time.sleep(1); subprocess.run(['docker','rm','-f',sys.argv[1]],check=True,stdout=subprocess.DEVNULL)",
                    held_id,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            owner.kill()
            owner.wait(timeout=3)
            assert owner.returncode == -9
            assert watchdog.wait(timeout=8) == 0
            assert (
                subprocess.run(
                    ["docker", "inspect", held_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode
                != 0
            )
            names.remove(held)
            if variant == "candidate":
                from factory_harness import run_script

                no_host = run_script(
                    session.host,
                    "return typeof std + typeof os + typeof process + typeof fetch;",
                    broker,
                )
                assert (
                    no_host["status"] == "executed" and "undefined" in no_host["output"]
                )
                before = len(control.authorizations)
                denied = run_script(
                    session.host, 'await tools.call("reserve",{});', broker
                )
                assert (
                    denied["status"] == "refused"
                    and len(control.authorizations) == before
                )
                timed = run_script(session.host, "while(true){}", broker, timeout=0.1)
                assert timed["status"] == "refused"
            from benchmark_acceptance import evaluate
            from container_evaluator import DockerEvaluator

            evaluation = evaluate(
                "intervals",
                workspace.snapshot(),
                DockerEvaluator(work, root / "evaluation"),
            )
            assert evaluation["accepted"] and evaluation["independent"], evaluation
            cancelled.set()
            try:
                server.dispatch({"type": "inference", "body": {}})
                raise AssertionError("cancel ignored")
            except Exception as error:
                assert str(error) == "attempt_closed"
            assert len(control.sends) == len(control.steps) + 1
            print(
                canonical(
                    {
                        "native_goose_mcp": True,
                        "synthetic_sends": len(control.sends),
                        "variant": variant,
                        "authorized_tools": len(control.authorizations),
                        "kernel_wrong_uid_denied": True,
                        "candidate_enabled": False,
                        "paid_inference": 0,
                        "independent_evaluation_accepted": evaluation["accepted"],
                        "filesystem_network_denials": True,
                        "independent_disposable_deadline_cleanup": True,
                        "creator_sigkill_cleanup": True,
                    }
                )
            )
        finally:
            cancelled.set()
            server.shutdown()
            server.server_close()
            thread.join(5)
            workspace.close()
            if variant == "candidate":
                session.artifacts.close()
            if guardian is not None:
                guardian.stdin.close()
                assert guardian.wait(timeout=8) == 0
                names.remove("sfactory-replay-" + token)
                assert (
                    subprocess.run(
                        ["docker", "inspect", ident],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    ).returncode
                    != 0
                )
            for name in names:
                docker("rm", "-f", name)
                assert (
                    subprocess.run(
                        ["docker", "inspect", name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    ).returncode
                    != 0
                )


if __name__ == "__main__":
    main()
