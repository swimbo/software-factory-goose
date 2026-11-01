"""Independent Docker evaluator with aggregate memory and tmpfs limits."""

import base64
import json
import os
from pathlib import Path, PurePosixPath
import stat
import selectors
import time
import subprocess
import uuid

IMAGE = "python@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2"
TMPFS = {
    "/work": "rw,nosuid,nodev,noexec,size=2m,nr_inodes=256,mode=0755",
    "/work/scratch": "rw,nosuid,nodev,noexec,size=1m,nr_inodes=128,uid=1001,gid=1001,mode=0700",
    "/tmp": "rw,nosuid,nodev,noexec,size=1m,nr_inodes=64,mode=1777",
}
CAPS = ["CHOWN", "SETUID", "SETGID", "KILL"]


def command(args, timeout=10):
    return subprocess.run(
        ["docker", *args], capture_output=True, timeout=timeout, check=True
    ).stdout


def attach_bounded(identity, payload):
    process = subprocess.Popen(
        ["docker", "start", "--attach", "--interactive", identity],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    pending = memoryview(payload)
    overflow = timed_out = False
    deadline = time.monotonic() + 15
    try:
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _ in selector.select(0.05):
                if key.data == "stdin":
                    try:
                        pending = pending[os.write(key.fd, pending[:4096]) :]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    raw = os.read(key.fd, 4096)
                    if not raw:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    else:
                        output[key.data].extend(raw)
                        if sum(map(len, output.values())) > 1048576:
                            overflow = True
            if overflow:
                break
    finally:
        if not overflow and not timed_out:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    return dict(
        exit_code=process.returncode,
        overflow=overflow,
        timed_out=timed_out,
        stdout=bytes(output["stdout"]),
        stderr=bytes(output["stderr"]),
    )


def fixture_path(name):
    if (
        not isinstance(name, str)
        or not name.startswith("scratch/")
        or any(p in ("", ".", "..") for p in name.split("/"))
    ):
        raise ValueError("fixture")
    return name


class DockerEvaluator:
    def __init__(self, source, evaluation_root):
        self.source, self.root = Path(source), Path(evaluation_root)

    def __call__(self, requests, fixtures):
        result = dict(
            exit_code=1,
            stdout=b"",
            stderr=b"evaluation denied",
            timed_out=False,
            overflow=False,
            sandbox_verified=False,
            cleanup_verified=False,
            files={},
            symlinks={},
            original_fd_bytes={},
        )
        name = "sfactory-evaluator-" + uuid.uuid4().hex
        owned = None
        try:
            source = {}
            total = count = 0
            for path in self.source.rglob("*"):
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    continue
                # Only the declared executable and public documentation/tests enter.
                relative = str(path.relative_to(self.source))
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_size > 1048576
                ):
                    raise ValueError("artifact")
                count += 1
                total += info.st_size
                if total > 1048576 or count > 128:
                    raise ValueError("artifact")
                if relative in ("solution.py", "README.md", "test_solution.py"):
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        now = os.fstat(fd)
                        if now.st_ino != info.st_ino or now.st_dev != info.st_dev:
                            raise ValueError("artifact")
                        raw = os.read(fd, 1048577)
                    finally:
                        os.close(fd)
                    source[relative] = base64.b64encode(raw).decode()
            if "solution.py" not in source or len(source) > 128:
                raise ValueError("artifact")
            setup = dict(
                files={},
                directories=list(fixtures["directories"]),
                symlinks=dict(fixtures["symlinks"]),
                pin_files=list(fixtures["pin_files"]),
            )
            for directory in setup["directories"]:
                if directory != "scratch":
                    fixture_path(directory)
            for name_, raw in fixtures["files"].items():
                fixture_path(name_)
                setup["files"][name_] = base64.b64encode(raw).decode()
            for name_, target in setup["symlinks"].items():
                fixture_path(name_)
                if not isinstance(target, str) or target.startswith("/"):
                    raise ValueError("fixture")
                components = list(PurePosixPath(name_).parent.parts)
                for part in target.split("/"):
                    if part == "..":
                        if len(components) <= 1:
                            raise ValueError("fixture")
                        components.pop()
                    elif part not in ("", "."):
                        components.append(part)
            for pin in setup["pin_files"]:
                if pin not in setup["files"]:
                    raise ValueError("fixture")
            payload = json.dumps(
                dict(source=source, requests=requests, fixtures=setup),
                separators=(",", ":"),
            ).encode()
            if len(payload) > 1572864:
                raise ValueError("input")
            security = json.loads(
                command(["info", "--format", "{{json .SecurityOptions}}"])
            )
            if "name=seccomp,profile=builtin" not in security:
                raise ValueError("default_seccomp")
            expected_image = json.loads(command(["image", "inspect", IMAGE]))[0]["Id"]
            helper = Path(__file__).with_name("container_eval_host.py").resolve()
            args = [
                "create",
                "--pull=never",
                "--name",
                name,
                "--interactive",
                "--network=none",
                "--read-only",
                "--log-driver=none",
                "--memory=128m",
                "--memory-swap=128m",
                "--cpus=1",
                "--pids-limit=16",
                "--shm-size=1m",
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--user=0:0",
                "--mount",
                f"type=bind,src={helper},dst=/trusted_helper.py,readonly",
            ]
            for cap in CAPS:
                args += ["--cap-add=" + cap]
            for destination, options in TMPFS.items():
                args += ["--tmpfs", destination + ":" + options]
            args += [IMAGE, "python3", "-I", "-B", "/trusted_helper.py"]
            owned = command(args).decode().strip()
            if len(owned) != 64 or any(c not in "0123456789abcdef" for c in owned):
                raise ValueError("identity")
            inspected = json.loads(command(["inspect", owned]))[0]
            config, host = inspected["Config"], inspected["HostConfig"]
            mounts = inspected["Mounts"]
            if not (
                inspected["Id"] == owned
                and inspected["Name"] == "/" + name
                and inspected["Image"] == expected_image
                and config["User"] == "0:0"
                and host["LogConfig"]["Type"] == "none"
                and host["NetworkMode"] == "none"
                and host["ReadonlyRootfs"]
                and host["ShmSize"] == 1048576
                and not host["Privileged"]
                and host["Memory"] == 134217728
                and host["MemorySwap"] == 134217728
                and host["NanoCpus"] == 1000000000
                and host["PidsLimit"] == 16
                and host["CapDrop"] == ["ALL"]
                and set(host["CapAdd"]) == {"CAP_" + cap for cap in CAPS}
                and host["SecurityOpt"] == ["no-new-privileges"]
                and host["Tmpfs"] == TMPFS
                and len(mounts) == 1
                and mounts[0]["Source"] == str(helper)
                and mounts[0]["Destination"] == "/trusted_helper.py"
                and not mounts[0]["RW"]
            ):
                raise ValueError("configuration")
            result["sandbox_verified"] = True
            execution = attach_bounded(owned, payload)
            if (
                execution["overflow"]
                or execution["timed_out"]
                or execution["exit_code"] != 0
            ):
                result.update(
                    overflow=execution["overflow"], timed_out=execution["timed_out"]
                )
            else:
                report = json.loads(execution["stdout"])
                if report.get("helper_failed"):
                    raise ValueError("helper")
                result.update(
                    {
                        key: report[key]
                        for key in ("exit_code", "overflow", "timed_out", "symlinks")
                    }
                )
                for key in ("stdout", "stderr"):
                    result[key] = base64.b64decode(report[key], validate=True)
                for key in ("files", "original_fd_bytes"):
                    result[key] = {
                        path: base64.b64decode(raw, validate=True)
                        for path, raw in report[key].items()
                    }
        except Exception:
            # Fail closed without raw Docker, host path, or exception disclosures.
            result["exit_code"] = 1
        finally:
            try:
                command(["rm", "--force", owned or name])
                # A second inspection must establish absence, not merely rm success.
                probe = subprocess.run(
                    ["docker", "container", "inspect", owned or name],
                    capture_output=True,
                    timeout=5,
                )
                result["cleanup_verified"] = (
                    probe.returncode == 1 and b"No such container" in probe.stderr
                )
            except Exception:
                result["cleanup_verified"] = False
            if not result["cleanup_verified"]:
                result["exit_code"] = 1
        return result
