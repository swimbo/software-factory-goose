#!/usr/bin/env python3
"""Run through ssh on the authorized Linux host; only random transient user units."""
import os
import pathlib
import subprocess
import tempfile
import time
import uuid

WORKER = '''import os,sys,time
root=sys.argv[1]
pid=os.fork()
if pid == 0:
    os.setsid()
    assert os.getsid(0)==os.getpid()
    open(root+"/ready.tmp","w").write(open("/proc/self/cgroup").read())
    os.replace(root+"/ready.tmp",root+"/ready")
    time.sleep(3)
    open(root+"/marker","w").write("alive")
    time.sleep(3)
    os._exit(0)
time.sleep(12)
'''

def run(*args, check=True, timeout=8):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=check)

def unit_value(unit, key):
    return run("systemctl", "--user", "show", unit, "--property="+key, "--value").stdout.strip()

def lane(root, positive):
    name = "sfactory-" + uuid.uuid4().hex + ".service"
    lane_dir = pathlib.Path(root, name)
    lane_dir.mkdir(mode=0o700)
    program = lane_dir / "worker.py"
    program.write_text(WORKER)
    attempted = False
    try:
        prior = run("systemctl", "--user", "show", name, "--property=LoadState", "--value", check=False)
        if prior.stdout.strip() not in ("not-found", ""):
            raise RuntimeError("unit name already exists")
        attempted = True
        run("systemd-run", "--user", "--unit="+name, "--collect", "--property=Description="+name, "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=15s", "--property=TimeoutStopSec=3s", "/usr/bin/python3", str(program), str(lane_dir))
        deadline = time.monotonic()+6
        while not (lane_dir/"ready").exists() and time.monotonic()<deadline:
            time.sleep(0.02)
        if not (lane_dir/"ready").exists():
            raise RuntimeError("escaped worker not ready")
        control = unit_value(name, "ControlGroup")
        if not control.startswith("/user.slice/user-1000.slice/") or name not in control:
            raise RuntimeError("unexpected cgroup identity: "+control)
        if (lane_dir/"ready").read_text().strip() != "0::"+control:
            raise RuntimeError("escaped child belongs to a different cgroup")
        events = pathlib.Path("/sys/fs/cgroup", control.lstrip("/"), "cgroup.events")
        fd = os.open(events, os.O_RDONLY)
        try:
            if "populated 1" not in os.read(fd, 4096).decode():
                raise RuntimeError("live populated positive control failed")
            if positive:
                deadline = time.monotonic()+5
                while not (lane_dir/"marker").exists() and time.monotonic()<deadline:
                    time.sleep(0.02)
                if not (lane_dir/"marker").exists():
                    raise RuntimeError("no-kill marker absent")
                print("POSITIVE_CONTROL: setsid child emitted marker", flush=True)
            else:
                # The manager resolves and signals the unit's own main process;
                # no numeric PID from persisted data is ever used.
                run("systemctl", "--user", "kill", "--kill-whom=main", "--signal=SIGKILL", name)
                empty = False
                observation = ""
                deadline = time.monotonic()+6
                while time.monotonic()<deadline:
                    try:
                        os.lseek(fd,0,os.SEEK_SET)
                        observation = os.read(fd,4096).decode()
                        if "populated 0" in observation:
                            empty = True
                            break
                    except OSError as exc:
                        observation = "observer error: "+str(exc)
                        break
                    time.sleep(0.002)
                time.sleep(3.5)
                marker = (lane_dir/"marker").exists()
                print("KILL_CONTROL: marker="+str(marker)+" empty="+str(empty)+" observation="+repr(observation),flush=True)
                if marker or not empty:
                    raise RuntimeError("cleanup or independently observed emptiness unproved")
        finally:
            os.close(fd)
    finally:
        if attempted:
            # Even after an ambiguous create, stop only a unit whose random
            # description and executable match this test-owned fixture.
            load = run("systemctl", "--user", "show", name, "--property=LoadState", "--value", check=False).stdout.strip()
            if load not in ("not-found", ""):
                desc = unit_value(name, "Description")
                executable = unit_value(name, "ExecStart")
                if desc != name or str(program) not in executable:
                    raise RuntimeError("fixture unit identity unresolved: "+name)
                stop = run("systemctl", "--user", "stop", name, check=False)
                state = run("systemctl", "--user", "show", name, "--property=ActiveState", "--value", check=False).stdout.strip()
                if stop.returncode and state not in ("inactive", "failed", ""):
                    raise RuntimeError("fixture cleanup unresolved for "+name)

with tempfile.TemporaryDirectory(prefix="sfactory-cgroup-") as root:
    lane(root, True)
    lane(root, False)
print("LIMIT: same-UID migration, independent brake authority, and host-manager loss unproven",flush=True)
