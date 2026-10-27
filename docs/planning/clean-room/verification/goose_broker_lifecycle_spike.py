#!/usr/bin/env python3
"""Protected same-UID Goose/MCP lifecycle fixture; no production launch admission.

The copied real MCP protocol adapter uses a fixture-only run_worker replacement:
one exact synthetic command selects one immutable broker catalogue entry. This
does not exercise execution's policy or masking implementation. Unknown commands
are refused. A PGID mismatch exits before any tool can launch.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from goose_factory_boundary_spike import FactoryStub


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=4)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call(root, route, value, brake=False):
    client = UnixHTTP(root / ("brake.sock" if brake else "broker.sock"))
    try:
        client.request("POST", route, json.dumps(value), {
            "Content-Type": "application/json",
            "x-brake-key" if brake else "x-spawn-key": ("5a" if brake else "69") * 32})
        response = client.getresponse()
        raw = response.read(3 * 1024 * 1024)
        if response.status != 200:
            raise RuntimeError(f"fixture {route} returned {response.status}")
        return json.loads(raw)
    finally:
        client.close()


def until(check, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.025)
    raise RuntimeError("bounded fixture condition timed out")


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return None


WRAPPER = r'''
import http.client, importlib.util, json, os, signal, socket, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv.pop(1))
sys.stderr = (root / "work" / "adapter-stderr.txt").open("w", buffering=1)
mode = sys.argv.pop(1)
group = {"pid": os.getpid(), "parent": os.getppid(), "pgid": os.getpgrp(),
         "parent_pgid": os.getpgid(os.getppid())}
group["inherited_owned_group"] = group["pgid"] == group["parent_pgid"] == group["parent"]
(root / "work" / "adapter-group.json").write_text(json.dumps(group))
if mode == "init_refusal":
    raise SystemExit("intentional fixture initialization refusal")
if not group["inherited_owned_group"]:
    raise SystemExit("fixture refused MCP outside its parent-owned process group")
spec = importlib.util.spec_from_file_location("factory_mcp", root.parent / "factory_mcp.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(str(root / "broker.sock"))
def broker(route, value):
    connection = UnixHTTP("localhost", timeout=3)
    try:
        connection.request("POST", route, json.dumps(value), {"Content-Type":"application/json", "x-spawn-key":"69"*32})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError("fixture broker unavailable")
        return json.loads(response.read(3*1024*1024))
    finally:
        connection.close()
def run_worker(request, execution, workdir, policy, cancelled, timeout):
    arguments = json.loads(request)
    if arguments != {"command":"fixture-approved"}:
        value = {"status":"refused", "reason":"policy_denied"}
    else:
        launch_id = json.loads((root / "registry.json").read_text())["launches"]["tool"]
        first = broker("/launch", {"launch_id":launch_id})
        assert first == broker("/launch", {"launch_id":launch_id})
        if mode == "hung":
            # Only this disposable adapter suspends itself; independent brake must work.
            (root / "work" / "adapter-hung").write_text("ready")
            os.kill(os.getpid(), signal.SIGSTOP)
        deadline = time.monotonic() + 15
        while True:
            if cancelled.is_set() or time.monotonic() >= deadline:
                return None
            result = broker("/result", {"launch_id":launch_id})
            if result["status"] == "running":
                time.sleep(.025)
                continue
            if result["status"] != "finished" or result["signal"] is not None:
                value = {"status":"refused", "reason":"output_withheld"}
            else:
                value = {"status":"executed", "exit_code":result["exit_code"],
                         "stdout":result["stdout"], "stderr":result["stderr"]}
            break
    return subprocess.CompletedProcess(["fixture-catalogue"], 0, json.dumps(value).encode(), b"")
adapter.run_worker = run_worker
adapter.main()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--broker", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--expect-group-refusal", action="store_true")
    parser.add_argument("--case", choices=["init_refusal", "normal", "denied", "hung"])
    parser.add_argument("--ordinary", action="store_true", help="ordinary Goose group-isolation control")
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit("Refusing overwrite")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Audited Darwin arm64 fixture only")
    goose, broker_binary = args.goose.resolve(), args.broker.resolve()
    if hashlib.sha256(goose.read_bytes()).hexdigest() != args.sha256:
        raise SystemExit("Unexpected Goose digest")
    broker_digest = hashlib.sha256(broker_binary.read_bytes()).hexdigest()
    repo = Path(__file__).resolve().parents[4]
    root = Path(tempfile.mkdtemp(prefix="sfgb-")).resolve()
    root.chmod(0o700)
    shutil.copyfile(repo / "clean-room/crates/execution/adapters/mcp_stdio.py", root / "factory_mcp.py")
    (root / "broker_adapter.py").write_text(WRAPPER)
    summary = {"fixture_only": True, "same_uid_only": True, "production_enabled": False,
        "goose_sha256": args.sha256, "broker_sha256": broker_digest,
        "adapter_sha256": hashlib.sha256((root / "factory_mcp.py").read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "expected_group_refusal": args.expect_group_refusal, "ordinary": args.ordinary, "cases": []}
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FactoryStub)
    provider.records = []
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    port = provider.server_address[1]
    cleanup_safe = True
    try:
        modes = ["group_refusal"] if args.expect_group_refusal else ["init_refusal", "normal", "denied", "hung"]
        if args.case:
            modes = [args.case]
        for mode in modes:
            case = root / mode
            case.mkdir(mode=0o700)
            work, home, state, tmp = [case / name for name in ("work", "home", "goose", "tmp")]
            for path in (work, home, state / "config", state / "data", state / "state", tmp):
                path.mkdir(parents=True)
            (state / "config/config.yaml").write_text("{}\n")
            (case / "policy.toml").write_text("# unused synthetic catalogue fixture\n")
            profile = case / "fixture.sb"
            profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                + '(allow file-write* (literal "/dev/null") '
                + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [work, state / "data", state / "state", tmp]) + ')\n'
                + f'(allow network-outbound (remote tcp "localhost:{port}") (literal {json.dumps(str(case / "broker.sock"))}))\n')
            environment = {"PATH":"/usr/bin:/bin", "HOME":str(home), "TMPDIR":str(tmp),
                "GOOSE_PATH_ROOT":str(state), "GOOSE_PROVIDER":"openai", "GOOSE_MODEL":"gpt-4o-mini",
                "OPENAI_HOST":f"http://127.0.0.1:{port}", "OPENAI_BASE_PATH":"v1/chat/completions",
                "OPENAI_API_KEY":"offline-fixture-not-a-credential", "GOOSE_DISABLE_SESSION_NAMING":"true",
                "GOOSE_TELEMETRY_ENABLED":"false", "GOOSE_MODE":"auto", "GOOSE_STATE_MACHINE":"0",
                "PYTHONNOUSERSITE":"1", "PYTHONDONTWRITEBYTECODE":"1"}
            # Verify actual network deny before running Goose. This process is independently owned here.
            guard = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(profile), "/usr/bin/python3", "-c",
                "import socket,errno;s=socket.socket();s.settimeout(.2);r=s.connect_ex(('198.51.100.1',443));raise SystemExit(0 if r==errno.EPERM else 1)"],
                env=environment, cwd=work, capture_output=True, timeout=4)
            if guard.returncode != 0:
                raise RuntimeError("network deny guard failed")
            extension = f"factory:/usr/bin/python3 {root / 'broker_adapter.py'} {case} {mode} --execution /usr/bin/true --workdir {work} --policy {case / 'policy.toml'} --timeout-secs 20"
            goose_argv = ["-f", str(profile), str(goose), "run", "--no-profile", "--no-session",
                "--max-turns", "3", "--output-format", "stream-json", "--with-extension", extension,
                "--text", "Offline fixture: call the factory tool requested by the provider."]
            if not args.ordinary:
                goose_argv.append("--factory-restricted")
            tool_script = ("sleep 60 & echo $$ $! > tool-group; kill -STOP $$; wait" if mode == "hung"
                           else "echo $$ > tool-group; printf VISIBLE_BROKER; printf STDERR_BROKER >&2; exit 7")
            catalogue = {
                "goose":{"program":"/usr/bin/sandbox-exec", "arguments":goose_argv, "cwd":str(work), "environment":environment, "stdin":""},
                "tool":{"program":"/bin/sh", "arguments":["-c",tool_script], "cwd":str(work), "environment":{}, "stdin":""},
                "worker":{"program":"/bin/sh", "arguments":["-c","echo $$ > worker-pid; kill -STOP $$; sleep 60"], "cwd":str(work), "environment":{}, "stdin":""}}
            (case / "catalogue.json").write_text(json.dumps(catalogue))
            (case / "catalogue.json").chmod(0o600)
            cleanup_safe = False
            server = subprocess.Popen([str(broker_binary),str(case)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH":"/usr/bin:/bin"})
            info = None
            offset = len(provider.records)
            provider.arguments = {"command":"unadmitted-command" if mode == "denied" else "fixture-approved"}
            try:
                info = until(lambda: read_json(case / "registry.json"), 5)
                if mode == "hung":
                    call(case, "/launch", {"launch_id":info["launches"]["worker"]})
                receipt = call(case, "/launch", {"launch_id":info["launches"]["goose"]})
                assert receipt == call(case, "/launch", {"launch_id":info["launches"]["goose"]})
                group = until(lambda: read_json(work / "adapter-group.json"))
                result = {"mode":mode, "adapter_group":group, "network_guard_denied":True}
                summary["cases"].append(result)
                if args.expect_group_refusal:
                    assert not group["inherited_owned_group"]
                    captured = until(lambda: finished(case, info["launches"]["goose"]))
                    assert not (work / "tool-group").exists()
                    result.update(group_mismatch_refused=True, tool_started=False, goose_exit_code=captured["exit_code"],
                                  goose_exit_zero_is_not_containment_proof=captured["exit_code"] == 0)
                elif mode == "init_refusal":
                    captured = until(lambda: finished(case, info["launches"]["goose"]))
                    result.update(goose_exit_code=captured["exit_code"], provider_requests=len(provider.records)-offset,
                                  tool_started=(work / "tool-group").exists())
                    assert captured["exit_code"] != 0 and not result["tool_started"]
                    assert result["provider_requests"] == 0
                    result["initialization_refusal_failed_closed"] = True
                elif mode == "hung":
                    assert group["inherited_owned_group"]
                    until(lambda:(work / "adapter-hung").exists() and (work / "tool-group").exists() and (work / "worker-pid").exists())
                    worker = int((work / "worker-pid").read_text())
                    tool_pids = [int(v) for v in (work / "tool-group").read_text().split()]
                    assert os.getpgid(worker) == worker and all(os.getpgid(pid) == tool_pids[0] for pid in tool_pids)
                    pids = [worker, group["parent"], group["pid"]] + tool_pids
                    for pid in (worker, group["pid"], tool_pids[0]):
                        until(lambda pid=pid: "T" in subprocess.check_output(["/bin/ps","-o","stat=","-p",str(pid)],text=True))
                    stopped = call(case,"/stop",{"target":info["family"]},brake=True)
                    assert len(stopped["groups"]) == 3 and stopped["leader_reaped"] and stopped["group_absent"]
                    until(lambda: all(absent(pid) for pid in pids))
                    assert call(case,"/stop",{"target":info["family"]},brake=True) == stopped
                    result.update(stop=stopped, all_five_processes_absent=True, three_suspended_processes=True)
                else:
                    assert group["inherited_owned_group"]
                    captured = until(lambda: finished(case, info["launches"]["goose"]))
                    result["captured_status"] = {"exit_code":captured["exit_code"], "signal":captured["signal"],
                                                 "completion_seen":"OFFLINE_FACTORY_DONE" in captured["stdout"]}
                    if captured["exit_code"] != 0 or "OFFLINE_FACTORY_DONE" not in captured["stdout"]:
                        result["synthetic_failure_stdout"] = captured["stdout"][-4000:]
                        result["synthetic_failure_stderr"] = captured["stderr"][-4000:]
                        result["synthetic_adapter_stderr"] = (work / "adapter-stderr.txt").read_text()[-4000:]
                        raise AssertionError("Goose fixture did not complete")
                    messages = [m for r in provider.records[offset:] for m in r["body"].get("messages",[]) if m.get("role") == "tool"]
                    responses = [json.loads(m["content"]) for m in messages]
                    expected = ({"status":"refused","reason":"policy_denied"} if mode == "denied" else
                                {"status":"executed","exit_code":7,"stdout":"VISIBLE_BROKER","stderr":"STDERR_BROKER"})
                    assert responses == [expected]
                    assert (work / "tool-group").exists() == (mode == "normal")
                    until(lambda: absent(group["pid"]) and absent(group["parent"]))
                    result.update(goose_exit_code=0, exact_adapter_response=expected, adapter_and_goose_absent=True)
            finally:
                try:
                    if info:
                        # Only the private family created in this fixture is targeted.
                        call(case,"/stop",{"target":info["family"]},brake=True)
                finally:
                    server.terminate()
                    stdout, stderr = server.communicate(timeout=6)
                    if server.returncode != 0:
                        raise RuntimeError("owned fixture server cleanup failed: " + stderr.decode(errors="replace")[:500])
                    cleanup_safe = True
        summary["negative_group_control_passed"] = args.expect_group_refusal
        summary["selected_cases_passed"] = True
        summary["bounded_lifecycle_passed"] = not args.expect_group_refusal and not args.case
    finally:
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=4)
        summary["owned_process_cleanup_verified"] = cleanup_safe
        summary["fixture_root_removed"] = cleanup_safe
        if cleanup_safe:
            shutil.rmtree(root)
        else:
            summary["retained_fixture_root"] = str(root)
        with args.summary.open("x") as output:
            json.dump(summary,output,indent=2)
            output.write("\n")
    print(json.dumps(summary,indent=2))


def finished(root, launch_id):
    result = call(root,"/result",{"launch_id":launch_id})
    if result["status"] == "running":
        return None
    if result["status"] != "finished":
        raise RuntimeError("fixture output withheld")
    return result


def absent(pid):
    try:
        os.kill(pid,0)
        return False
    except ProcessLookupError:
        return True


if __name__ == "__main__":
    main()
