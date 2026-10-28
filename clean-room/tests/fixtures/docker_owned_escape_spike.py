#!/usr/bin/env python3
"""Disposable Docker experiment; never use an existing container as a target."""
import json
import subprocess
import sys
import time
import uuid

IMAGE = "sha256:1f36a4037bc906e68f59d9f3065265ac24be76ffc22fbf0a4c610a8467ebc30d"
LABEL = "org.software-factory.escape-spike"

ESCAPED = '''import os,sys,time
assert os.getsid(0) == os.getpid()
os.write(int(sys.argv[2]),b"R")
print("ESCAPE_READY",flush=True)
assert os.read(int(sys.argv[1]),1) == b"G"
print("ESCAPED_AFTER_GUARDIAN",flush=True)
time.sleep(3)
print("LATE_MARKER",flush=True)
time.sleep(1)
'''
# A pipe from the guardian would close when it dies, so escaped output goes directly
# to container stderr, not through the guardian's pipe.
GUARDIAN = '''import os,subprocess,sys,time
gate=int(sys.argv[1]); ready_r,ready_w=os.pipe()
child=subprocess.Popen([sys.executable,"-u","-c",%r,str(gate),str(ready_w)],stdout=sys.stderr,start_new_session=True,pass_fds=(gate,ready_w))
os.close(ready_w)
assert os.read(ready_r,1)==b"R"
print("GUARDIAN_READY",flush=True)
time.sleep(8)
''' % ESCAPED
MAIN = '''import os,subprocess,sys,time
gate_r,gate_w=os.pipe()
p=subprocess.Popen([sys.executable,"-u","-c",%r,str(gate_r)],stdout=subprocess.PIPE,text=True,pass_fds=(gate_r,))
os.close(gate_r)
assert p.stdout.readline().strip()=="GUARDIAN_READY"
print("GUARDIAN_READY",flush=True)
p.kill(); p.wait()
print("GUARDIAN_REAPED",flush=True)
os.write(gate_w,b"G"); os.close(gate_w)
time.sleep(8)
''' % GUARDIAN

def run(*args, check=True, timeout=8):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=check)

def owned(name, token):
    result = run("inspect", "--format", '{{json .Config.Labels}}', name, check=False)
    if result.returncode:
        if "no such object" in result.stderr.lower():
            return False
        raise RuntimeError("cannot establish container identity " + name + ": " + result.stderr.strip())
    return json.loads(result.stdout).get(LABEL) == token

def lane(kill):
    token = uuid.uuid4().hex
    name = "sf-escape-spike-" + token
    target = None
    try:
        result = run("create", "--name", name, "--label", LABEL + "=" + token,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "24",
            "--memory", "96m", "--cpus", "0.5", "--user", "65534:65534",
            "--entrypoint", "python3", "--pull", "never", IMAGE, "-u", "-c", MAIN)
        target = result.stdout.strip()
        if not target or not owned(target, token):
            raise RuntimeError("container identity could not be confirmed")
        run("start", target)
        deadline = time.monotonic() + 12
        logs = ""
        while time.monotonic() < deadline:
            result = run("logs", target, check=False)
            logs = result.stdout + result.stderr
            if all(x in logs for x in ("ESCAPE_READY", "GUARDIAN_REAPED", "ESCAPED_AFTER_GUARDIAN")):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("escape/guardian handshake not observed: " + logs)
        if kill:
            if "LATE_MARKER" in logs:
                raise RuntimeError("late marker preceded kill")
            run("kill", target)
            run("wait", target)
            time.sleep(3.5)
            result = run("logs", target, check=False)
            logs = result.stdout + result.stderr
            if "LATE_MARKER" in logs:
                raise RuntimeError("late marker observed after kill")
            state = run("inspect", "--format", '{{.State.Running}} {{.State.ExitCode}}', target).stdout.strip()
            if not state.startswith("false "):
                raise RuntimeError("engine did not report stopped: " + state)
            print("KILL_CONTROL: guardian reaped; escaped heartbeat observed; no late log; engine stopped", flush=True)
        else:
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                result = run("logs", target, check=False)
                if "LATE_MARKER" in result.stdout + result.stderr:
                    print("POSITIVE_CONTROL: escaped process emitted late log", flush=True)
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("positive late marker absent")
    finally:
        candidate = target or name
        if owned(candidate, token):
            run("rm", "--force", candidate, check=True)
        elif target:
            raise RuntimeError("cleanup identity unavailable; inspect owned container manually: " + target)

def main():
    observed = run("image", "inspect", "--format", "{{.Id}}", IMAGE).stdout.strip()
    if observed != IMAGE:
        raise RuntimeError("pinned local image identity unavailable")
    lane(False)
    lane(True)
    print("LIMIT: no independent cgroup-empty observation or automatic owner-loss brake", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAILED:", exc, file=sys.stderr)
        sys.exit(1)
