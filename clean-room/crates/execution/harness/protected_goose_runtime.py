"""Protected native Goose attempt adapter. No implicit provider or budget backend.

The supervisor supplies authenticated launch/accounting/transport services. The
Darwin implementation is for explicit rehearsal only; live activation requires
the independently attested Linux identities, cgroup and gateway contract.
"""

import hashlib
from contextlib import ExitStack
import ctypes
import errno
import http.server
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time

from factory_harness import Broker, Denied, Profile, StallDetector, Tool, canonical
from container_evaluator import DockerEvaluator
from harness_session import CandidateSession
from harness_evaluation import observation

GOOSE_SHA256 = "512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb"
MAX_BYTES = 1048576
NATIVE_PYTHON = Path("/Library/Developer/CommandLineTools/usr/bin/python3").resolve()


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def profile_fingerprints(
    goose,
    host,
    normalizer,
    *,
    model,
    route,
    max_request_bytes=65536,
    max_output_tokens=16384,
):
    from benchmark_acceptance import INTERFACES

    names = (
        "protected_goose_runtime.py",
        "protected_mcp.py",
        "container_evaluator.py",
        "container_eval_host.py",
        "protected_spending_control.py",
        "billing_receipts.py",
        "billing_spending.py",
        "billing_capabilities.py",
        "usage_rating.py",
        "usage_spending.py",
        "physical_usage.py",
        "physical_settlement.py",
        "gateway_custody.py",
        "gateway_transport.py",
        "factory_harness.py",
        "harness_mcp.py",
        "harness_session.py",
        "harness_evaluation.py",
        "candidate-profile.json",
        "benchmark-spending-policy.json",
    )
    common = {
        "version": 1,
        "model": model,
        "route": route,
        "max_request_bytes": max_request_bytes,
        "max_output_tokens": max_output_tokens,
        "public_interoperability_contract_sha256": sha(INTERFACES),
        "code": {
            name: hashlib.sha256(
                Path(__file__).with_name(name).read_bytes()
            ).hexdigest()
            for name in names
        },
        "binaries": {
            name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for name, path in (
                ("goose", goose),
                ("script_host", host),
                ("normalizer", normalizer),
            )
        },
    }
    return {
        variant: sha(common | {"variant": variant})
        for variant in ("baseline", "candidate")
    }


def assistant_shape(value):
    # Comparison only. Never rewrite the provider request or a signed payload.
    result = json.loads(canonical(value))
    if result.get("content") in (None, ""):
        result["content"] = None
    for call in result.get("tool_calls", []):
        call["function"]["arguments"] = json.loads(call["function"]["arguments"])
    return canonical(result)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate_json_field")
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(
        raw,
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(Denied("invalid_json")),
    )


def store_private(path, value):
    data = canonical(value).encode()
    if len(data) > 16384:
        raise Denied("receipt_overflow")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1
            or not 0 < st.st_size <= 16384
        ):
            raise Denied("receipt_unavailable")
        raw = stream.read(16385)
        if len(raw) != st.st_size:
            raise Denied("receipt_changed")
        return parse_json(raw)


def _owned_exited(pid):
    if hasattr(os, "waitid"):
        return (
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        )
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise Denied("wait_ownership_unavailable")
    # Darwin SDK sys/signal.h: first four siginfo_t fields are int signo,
    # errno, code, pid. An oversized aligned buffer holds the entire structure.
    info = (ctypes.c_uint64 * 128)()
    libc = ctypes.CDLL(None, use_errno=True)
    waitid = libc.waitid
    waitid.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int]
    waitid.restype = ctypes.c_int
    while waitid(1, pid, ctypes.byref(info), os.WEXITED | os.WNOHANG | os.WNOWAIT) != 0:
        if ctypes.get_errno() != errno.EINTR:
            raise Denied("wait_ownership_lost")
    return ctypes.cast(info, ctypes.POINTER(ctypes.c_int))[3] == pid


def _darwin_group_members(pid):
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_listpids
    function.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_int
    pids = (ctypes.c_int * 1024)()
    count = function(2, pid, ctypes.byref(pids), ctypes.sizeof(pids))
    if count < 0 or count >= ctypes.sizeof(pids) or count % ctypes.sizeof(ctypes.c_int):
        raise Denied("process_cleanup_unverified")
    return set(pids[: count // ctypes.sizeof(ctypes.c_int)]) - {0}


def run_bounded(argv, *, cwd, env, input_bytes=b"", timeout=30):
    """Hold the leader unreaped until group cleanup; never signal recycled IDs.

    Callers must contain fork/exec and session creation in the OS boundary. This
    process-group helper alone does not establish a general Linux cgroup proof.
    """
    if len(input_bytes) > 65536 or not 0 < timeout <= 300:
        raise Denied("invalid_process_request")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = timed_out = False
    pending = memoryview(input_bytes)
    deadline = time.monotonic() + timeout
    try:
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if pending:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(0.1, remaining)):
                if key.data == "stdin":
                    try:
                        count = os.write(key.fd, pending[:4096])
                        pending = pending[count:]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    if sum(map(len, output.values())) > MAX_BYTES:
                        overflow = True
                        break
            if overflow:
                break
    finally:
        selector.close()
        # Non-reaping kernel observation verifies ownership even for an exited
        # leader. Darwin returns EPERM for an empty zombie-led group.
        _owned_exited(process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            if (
                platform.system() != "Darwin"
                or not _owned_exited(process.pid)
                or _darwin_group_members(process.pid) - {process.pid}
            ):
                raise Denied("process_cleanup_unverified") from None
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    return {
        "exit_code": process.returncode,
        "stdout": b"" if overflow else bytes(output["stdout"]),
        "stderr": b"" if overflow else bytes(output["stderr"]),
        "overflow": overflow,
        "timed_out": timed_out,
    }


class BoundedWorkspace:
    """Typed attempt-only files, no symlink ancestors, dotfiles or caller root."""

    def __init__(self, root, normalize):
        self.root = Path(root).resolve()
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.normalize = normalize

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def parent(self, path, create=False):
        if (
            not isinstance(path, str)
            or len(path) > 256
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", path)
        ):
            raise Denied("invalid_path")
        parts = path.split("/")
        if len(parts) > 8 or any(not p or p.startswith(".") for p in parts):
            raise Denied("invalid_path")
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except Exception:
            os.close(fd)
            raise Denied("invalid_path") from None

    def read(self, args):
        if not isinstance(args, dict) or set(args) != {"path"}:
            raise Denied("invalid_arguments")
        parent, name = self.parent(args["path"])
        try:
            try:
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
                with os.fdopen(fd, "rb") as stream:
                    st = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(st.st_mode)
                        or st.st_nlink != 1
                        or st.st_size > 65536
                    ):
                        raise Denied("invalid_file")
                    raw = stream.read(65537)
                    if len(raw) != st.st_size:
                        raise Denied("file_changed")
                    return raw.decode("utf-8", "strict")
            except (OSError, UnicodeError):
                raise Denied("invalid_file") from None
        finally:
            os.close(parent)

    def write(self, args):
        if (
            not isinstance(args, dict)
            or set(args) != {"path", "content"}
            or not isinstance(args["content"], str)
            or len(args["content"].encode()) > 32768
        ):
            raise Denied("invalid_arguments")
        content = self.normalize(args["content"]).encode()
        if len(content) > 32768:
            raise Denied("file_overflow")
        existing = self._manifest()
        total = sum(length for length, _ in existing.values())
        previous = existing.get(args["path"], (0, ""))[0]
        if total - previous + len(content) > MAX_BYTES or (
            args["path"] not in existing and len(existing) >= 128
        ):
            raise Denied("workspace_overflow")
        parent, name = self.parent(args["path"], create=True)
        temporary = "sfactory-write-" + secrets.token_hex(12)
        try:
            try:
                st = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise Denied("invalid_file")
            except FileNotFoundError:
                pass
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            self.snapshot()
            return "File written."
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def _manifest(self):
        values, total = {}, 0
        for current, dirs, files in os.walk(self.root, followlinks=False):
            dirs.sort()
            files.sort()
            for name in dirs:
                if (Path(current) / name).is_symlink():
                    raise Denied("invalid_workspace")
            for name in files:
                relative = str((Path(current) / name).relative_to(self.root))
                raw = self.read({"path": relative}).encode()
                total += len(raw)
                if len(values) >= 128 or total > MAX_BYTES:
                    raise Denied("workspace_overflow")
                values[relative] = (len(raw), hashlib.sha256(raw).hexdigest())
        return values

    def snapshot(self):
        return sha(sorted(self._manifest().items()))

    def listing(self, args):
        if args != {}:
            raise Denied("invalid_arguments")
        return canonical(sorted(self._manifest()))

    def tools(self):
        path = {"type": "string", "maxLength": 256}

        def schema(properties):
            return {
                "type": "object",
                "properties": properties,
                "required": list(properties),
                "additionalProperties": False,
            }

        return [
            Tool(
                "read_file",
                "Read an attempt-owned UTF-8 file.",
                schema({"path": path}),
                True,
                self.read,
            ),
            Tool(
                "write_file",
                "Write an attempt-owned UTF-8 file.",
                schema(
                    {"path": path, "content": {"type": "string", "maxLength": 32768}}
                ),
                False,
                self.write,
            ),
            Tool(
                "list_files",
                "List attempt-owned files.",
                schema({}),
                True,
                self.listing,
            ),
        ]


class BaselineSession:
    def __init__(self, broker, snapshot, cancelled, deadline):
        self.broker, self.snapshot, self.cancelled, self.deadline = (
            broker,
            snapshot,
            cancelled,
            deadline,
        )
        self.profile = broker.profile
        self.lock = threading.Lock()
        self.stalls = StallDetector()

    def declarations(self):
        return [
            self.profile.tools[name].declaration()
            for name in sorted(self.profile.tools)
        ]

    def call(self, name, arguments):
        if not self.lock.acquire(False):
            return {"status": "refused", "reason": "busy"}
        try:
            if self.cancelled.is_set() or time.monotonic() >= self.deadline:
                raise Denied("attempt_closed")
            if self.stalls.stalled:
                return {"status": "stalled"}
            before = self.snapshot()
            error = None
            try:
                value = self.broker.call(name, arguments)
                result = {"status": "executed", "output": value}
            except Exception:
                error = "tool_failed"
                result = {"status": "refused", "reason": error}
            state = self.stalls.observe(
                self.snapshot(), error, before != self.snapshot()
            )
            if state in ("intervene", "stalled"):
                return {"status": "intervention" if state == "intervene" else "stalled"}
            return result
        except Exception:
            return {"status": "refused", "reason": "execution_unavailable"}
        finally:
            self.lock.release()


def parse_completion(raw, normalize, models, tool_names):
    """Complete bounded SSE response, then masking before any worker publication."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise Denied("response_overflow")
    try:
        text = raw.decode("utf-8", "strict").replace("\r\n", "\n")
        if "\r" in text or not text.endswith("\n"):
            raise Denied("invalid_stream")
        frames, pending = [], None
        for line in text.split("\n")[:-1]:
            if line.startswith(":"):
                continue
            if not line:
                if pending is not None:
                    frames.append(pending)
                    pending = None
                continue
            if not line.startswith("data: ") or pending is not None:
                raise Denied("invalid_stream")
            pending = line[6:]
        if pending is not None:
            raise Denied("invalid_stream")
        events, done = [], False
        assistant, calls = {"role": "assistant", "content": ""}, {}
        finish = None
        for data in frames:
            if done:
                raise Denied("invalid_stream")
            if data == "[DONE]":
                done = True
                continue
            event = parse_json(data)
            if event.get("model") not in models:
                raise Denied("unreviewed_model")
            choices = event.get("choices")
            if choices == [] and isinstance(event.get("usage"), dict):
                events.append(event)
                continue
            if finish is not None:
                raise Denied("data_after_completion")
            if (
                not isinstance(choices, list)
                or len(choices) != 1
                or choices[0].get("index") != 0
            ):
                raise Denied("invalid_stream")
            choice, delta = choices[0], choices[0].get("delta")
            if not isinstance(delta, dict) or set(delta) - {
                "role",
                "content",
                "tool_calls",
                "reasoning_content",
            }:
                raise Denied("invalid_stream")
            if delta.get("role") not in (None, "assistant"):
                raise Denied("invalid_stream")
            for field in ("content", "reasoning_content"):
                value = delta.get(field)
                if value is not None:
                    if not isinstance(value, str):
                        raise Denied("invalid_stream")
                    assistant[field] = assistant.get(field, "") + value
            for item in delta.get("tool_calls", []):
                i = item["index"]
                if type(i) is not int or not 0 <= i < 8:
                    raise Denied("invalid_stream")
                target = calls.setdefault(
                    i,
                    {
                        "id": "",
                        "type": "function",
                        "function": {"name": "", "arguments": ""},
                    },
                )
                target["id"] += item.get("id", "")
                for field in ("name", "arguments"):
                    target["function"][field] += item.get("function", {}).get(field, "")
            if choice.get("finish_reason") is not None:
                if finish is not None:
                    raise Denied("invalid_stream")
                finish = choice["finish_reason"]
            events.append(event)
        if not done or finish not in ("stop", "tool_calls"):
            raise Denied("incomplete_stream")
        if sorted(calls) != list(range(len(calls))):
            raise Denied("invalid_tool_calls")
        values = [calls[i] for i in sorted(calls)]
        if bool(values) != (finish == "tool_calls") or len(
            {c["id"] for c in values}
        ) != len(values):
            raise Denied("invalid_tool_calls")
        for call in values:
            if (
                not call["id"]
                or call["function"]["name"] not in tool_names
                or not isinstance(json.loads(call["function"]["arguments"]), dict)
            ):
                raise Denied("invalid_tool_calls")
        if values:
            assistant["content"] = assistant["content"] or None
            assistant["tool_calls"] = values
        for field in ("content", "reasoning_content"):
            if isinstance(assistant.get(field), str):
                assistant[field] = normalize(assistant[field])
        for call in values:
            call["id"] = normalize(call["id"])
            call["function"]["arguments"] = normalize(call["function"]["arguments"])
            if not isinstance(json.loads(call["function"]["arguments"]), dict):
                raise Denied("normalized_arguments_unavailable")
        if any(
            not isinstance(c["id"], str) or not 0 < len(c["id"].encode()) <= 128
            for c in values
        ) or len({c["id"] for c in values}) != len(values):
            raise Denied("normalized_tool_identity_unavailable")
        # Publish only the normalized complete logical response, not the original
        # chunks. A credential split across chunks must never be reconstructed raw.
        delta = json.loads(canonical(assistant))
        for index, call in enumerate(delta.get("tool_calls", [])):
            call["index"] = index
        first = events[0]
        envelope = {
            k: first[k] for k in ("id", "model", "created", "object") if k in first
        }
        if "id" in envelope:
            if not isinstance(envelope["id"], str):
                raise Denied("invalid_stream")
            envelope["id"] = normalize(envelope["id"])
        if (
            "object" in envelope
            and envelope["object"] != "chat.completion.chunk"
            or "created" in envelope
            and (
                type(envelope["created"]) is not int
                or not 0 <= envelope["created"] < 2**63
            )
        ):
            raise Denied("unsupported_stream_metadata")
        normalized_events = [
            envelope
            | {"choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
        ]
        last = envelope | {
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]
        }
        usage = next(
            (e["usage"] for e in reversed(events) if isinstance(e.get("usage"), dict)),
            None,
        )
        if usage is not None:

            def valid_usage(value, depth=0):
                if value is None or type(value) is int and value >= 0:
                    return True
                return (
                    type(value) is dict
                    and depth < 4
                    and len(value) <= 32
                    and all(
                        isinstance(k, str)
                        and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", k)
                        and normalize(k) == k
                        and valid_usage(v, depth + 1)
                        for k, v in value.items()
                    )
                )

            if not valid_usage(usage):
                raise Denied("unsupported_usage_metadata")
            last["usage"] = usage
        normalized_events.append(last)
        normalized = (
            "".join("data: " + canonical(e) + "\n\n" for e in normalized_events)
            + "data: [DONE]\n\n"
        ).encode()
        if len(normalized) > MAX_BYTES:
            raise Denied("response_overflow")
        return normalized, assistant, [c["id"] for c in values]
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        raise Denied("invalid_stream") from None


def seatbelt(read_paths, write_paths, port=None, *, no_fork=False):
    if platform.system() != "Darwin":
        raise Denied("unsupported_native_boundary")
    # No blanket temporary-directory or home read exception. Evaluator source,
    # receipts, credentials and sibling attempts remain outside these paths.
    allowed = [
        Path("/System/Library"),
        Path("/System/Volumes/Preboot/Cryptexes/OS"),
        Path("/usr/lib"),
        Path("/usr/bin"),
        Path("/usr/share"),
        Path("/Library/Apple"),
        Path(
            "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework"
        ),
        Path("/private/var/db/timezone"),
        Path("/dev/null"),
        Path("/dev/urandom"),
        Path("/dev/random"),
    ]
    values = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny file-read*)",
        "(deny file-write*)",
        "(deny signal)",
        # Current Darwin dyld opens the root directory before mapping its cache.
        # Literal directory access is not a recursive filesystem read exception.
        '(allow file-read-data (literal "/"))',
    ]
    values.append(
        "(allow file-read* "
        + " ".join(
            "(subpath " + json.dumps(str(p.resolve())) + ")"
            for p in allowed + list(read_paths)
        )
        + ")"
    )
    ancestors = set()
    for path in allowed + list(read_paths) + list(write_paths):
        ancestors.update(path.resolve().parents)
    values.append(
        "(allow file-read-metadata "
        + " ".join("(literal " + json.dumps(str(p)) + ")" for p in sorted(ancestors))
        + ")"
    )
    values.append(
        '(allow file-write* (literal "/dev/null") '
        + " ".join(
            "(subpath " + json.dumps(str(p.resolve())) + ")" for p in write_paths
        )
        + ")"
    )
    if port is not None:
        values.append(f'(allow network-outbound (remote tcp "localhost:{port}"))')
    if no_fork:
        values.append("(deny process-fork)")
    return "\n".join(values) + "\n"


class ModelRelay:
    """One transcript, one capability, same authority for all model and tool calls.

    control.exchange is the trusted protected transport: it must reserve/begin in
    the sole journal, dispatch once, close the complete physical-call manifest and
    settle actual receipts before returning. Missing billing must leave Unknown.
    No key, endpoint, price, day or scope can be supplied in an HTTP request.
    """

    def __init__(self, attempt, session, control, prompt, token, normalize, deadline):
        self.attempt, self.session, self.control = attempt, session, control
        self.prompt, self.token, self.normalize, self.deadline = (
            prompt,
            token,
            normalize,
            deadline,
        )
        self.lock = threading.RLock()
        self.requests, self.records, self.assistant, self.tool_results = (
            [],
            [],
            None,
            [],
        )
        self.failed = False
        self.failure_reason = None
        self.metrics = []
        self.inference_attempts = 0

    def tool(self, name, arguments):
        with self.lock:
            if self.failed or self.assistant is None:
                raise Denied("tool_unavailable")
            expected = self.assistant.get("tool_calls", [])
            index = len(self.tool_results)
            if index >= len(expected):
                raise Denied("unexpected_tool")
            tool = expected[index]
            if name != tool["function"]["name"].removeprefix("factory__") or canonical(
                arguments
            ) != canonical(json.loads(tool["function"]["arguments"])):
                raise Denied("unattested_tool")
            result = self.session.call(name, arguments)
            self.tool_results.append((tool["id"], result))
            return result

    def exchange(self, body):
        with self.lock:
            if (
                self.failed
                or time.monotonic() >= self.deadline
                or len(self.records) >= 32
            ):
                raise Denied("attempt_closed")
            try:
                if (
                    not isinstance(body, dict)
                    or body.get("model") != "auto"
                    or body.get("stream") is not True
                ):
                    raise Denied("invalid_provider_request")
                if (
                    type(body.get("max_tokens")) is not int
                    or not 0 < body["max_tokens"] <= 16384
                ):
                    raise Denied("invalid_provider_request")
                declarations = {
                    "factory__" + t["name"]: t for t in self.session.declarations()
                }
                offered = [t["function"]["name"] for t in body["tools"]]
                if len(offered) != len(declarations) or set(offered) != set(
                    declarations
                ):
                    raise Denied("invalid_provider_tools")
                messages = body["messages"]
                if not self.requests:
                    if (
                        len(messages) != 2
                        or messages[0].get("role") != "system"
                        or messages[1].get("role") != "user"
                        or not messages[1].get("content", "").startswith(self.prompt)
                    ):
                        raise Denied("invalid_initial_transcript")
                else:
                    previous = self.requests[-1]
                    if set(body) != set(previous) or any(
                        canonical(body.get(k)) != canonical(v)
                        for k, v in previous.items()
                        if k != "messages"
                    ):
                        raise Denied("provider_configuration_changed")
                    calls = self.assistant.get("tool_calls", [])
                    if (
                        not calls
                        or len(self.tool_results) != len(calls)
                        or len(messages) != len(previous["messages"]) + 1 + len(calls)
                    ):
                        raise Denied("unattested_continuation")
                    if messages[: len(previous["messages"])] != previous["messages"]:
                        raise Denied("unattested_continuation")
                    candidate = messages[len(previous["messages"])]
                    if assistant_shape(candidate) != assistant_shape(self.assistant):
                        raise Denied("unattested_assistant")
                    for message, (tool_id, result) in zip(
                        messages[-len(calls) :], self.tool_results
                    ):
                        if (
                            message.get("role") != "tool"
                            or message.get("tool_call_id") != tool_id
                            or canonical(json.loads(message["content"]))
                            != canonical(result)
                        ):
                            raise Denied("unattested_tool_result")
                # Any failure AFTER this point may represent a paid unknown send.
                request_sha256 = sha(body)
                self.inference_attempts += 1
                call_start = time.monotonic()
                response = self.control.exchange(self.attempt, body, len(self.records))
                if sha(body) != request_sha256:
                    raise Denied("provider_request_changed")
                raw, assistant, _ = parse_completion(
                    response["sse"], self.normalize, {"auto"}, set(declarations)
                )
                record = {
                    k: response[k]
                    for k in (
                        "call_id",
                        "physical_manifest_sha256",
                        "billing_receipt_sha256",
                    )
                }
                record["request_sha256"] = sha(body)
                if (
                    not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", record["call_id"])
                    or any(
                        not re.fullmatch(r"[0-9a-f]{64}", record[k])
                        for k in record
                        if k != "call_id"
                    )
                    or record["call_id"] in [r["call_id"] for r in self.records]
                ):
                    raise Denied("invalid_transport_receipt")
                self.records.append(record)
                self.requests.append(body)
                usage = None
                for line in response["sse"].decode("utf-8", "strict").splitlines():
                    if line.startswith("data: ") and line != "data: [DONE]":
                        event = parse_json(line[6:])
                        if isinstance(event.get("usage"), dict):
                            usage = event["usage"]
                measured = observation(
                    body,
                    usage,
                    goose_build=self.attempt["goose_build"],
                    profile=self.attempt["profile"],
                    model=self.attempt["model"],
                    route=self.attempt["route"],
                    tool_result_bytes=sum(
                        len(m.get("content", "").encode())
                        for m in messages
                        if m.get("role") == "tool"
                    ),
                    billed_microusd=response.get("billed_microusd"),
                    usage_rated_microusd=response.get("usage_rated_microusd"),
                    cost_basis=response.get("cost_basis"),
                    tariff_sha256=response.get("tariff_sha256"),
                    elapsed_ms=max(1, int((time.monotonic() - call_start) * 1000)),
                )
                self.metrics.append(
                    {
                        k: v
                        for k, v in measured.items()
                        if k
                        not in (
                            "version",
                            "goose_build",
                            "profile",
                            "model",
                            "route",
                            "accepted",
                        )
                    }
                )
                self.assistant, self.tool_results = assistant, []
                return raw
            except Exception as error:
                self.failed = True
                self.failure_reason = (
                    str(error)
                    if isinstance(error, Denied)
                    and re.fullmatch(r"[a-z_]{1,80}", str(error))
                    else "relay_error"
                )
                self.session.cancelled.set()
                raise Denied("provider_outcome_unavailable") from None


class RelayHandler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def reply(self, value, *, stream=False):
        raw = value if stream else canonical(value).encode()
        self.send_response(200)
        self.send_header(
            "Content-Type", "text/event-stream" if stream else "application/json"
        )
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        headers = self.headers.get_all("Authorization", [])
        return len(headers) == 1 and secrets.compare_digest(
            headers[0], "Bearer " + self.server.relay.token
        )

    def do_GET(self):
        if not self.authorized() or self.path != "/v1/models":
            self.send_error(403)
            return
        self.reply(
            {
                "object": "list",
                "data": [
                    {"id": "auto", "object": "model", "owned_by": "protected-factory"}
                ],
            }
        )

    def do_POST(self):
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (
                not self.authorized()
                or len(lengths) != 1
                or self.headers.get("Transfer-Encoding")
                or not lengths[0].isascii()
                or not lengths[0].isdecimal()
                or not 0 < int(lengths[0]) <= 65536
            ):
                raise Denied("invalid_http_request")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise Denied("invalid_http_request")
            value = parse_json(raw)
            relay = self.server.relay
            if self.path == "/factory/list" and value == {}:
                self.reply(relay.session.declarations())
            elif self.path == "/factory/cancel" and value == {}:
                relay.session.cancelled.set()
                self.reply({"cancelled": True})
            elif (
                self.path == "/factory/call"
                and isinstance(value, dict)
                and set(value) == {"name", "arguments"}
            ):
                self.reply(relay.tool(value["name"], value["arguments"]))
            elif self.path == "/v1/chat/completions":
                self.reply(relay.exchange(value), stream=True)
            else:
                raise Denied("unknown_operation")
        except Exception:
            self.send_error(502, "protected attempt unavailable")


class RelayServer(http.server.ThreadingHTTPServer):
    def __init__(self, address):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, RelayHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class ProtectedGooseAdapter:
    """Runner API, actual pinned Goose, external authenticated authority and billing.

    control.admit/authorize_tool/exchange/billing/revoke are trusted fixed-owner
    interfaces. This class cannot create a price contract, grant or invoice. The
    native Darwin rehearsal must never be admitted as a Linux live benchmark.
    """

    def __init__(self, root, suite, *, goose, host, normalizer, control):
        self.root, self.suite, self.control = Path(root).resolve(), suite, control
        self.goose, self.host, self.normalizer = map(
            lambda p: Path(p).resolve(), (goose, host, normalizer)
        )
        if (
            platform.system() != "Darwin"
            or platform.machine() != "arm64"
            or hashlib.sha256(self.goose.read_bytes()).hexdigest() != GOOSE_SHA256
        ):
            raise Denied("unverified_goose_boundary")
        self.root.mkdir(mode=0o700, exist_ok=True)
        st = self.root.lstat()
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700
        ):
            raise Denied("invalid_runtime_root")
        self.generated = {}
        self.profiles = profile_fingerprints(
            self.goose,
            self.host,
            self.normalizer,
            model=control.config["model"],
            route=control.config["route_sha256"],
            max_request_bytes=control.config.get("max_request_bytes", 65536),
            max_output_tokens=control.config.get("max_output_tokens", 16384),
        )

    def admit(self, attempt):
        if (
            attempt["mode"] != "rehearsal"
            or attempt["goose_build"] != GOOSE_SHA256
            or attempt.get("profile") != self.profiles.get(attempt.get("variant"))
        ):
            # Preserve the existing distinct-UID/cgroup activation gate. No flag or
            # caller boolean substitutes for a Linux protected launch attestation.
            return {
                "attempt_id": attempt["attempt_id"],
                "status": "denied",
                "authority_receipt_sha256": sha(
                    {
                        "reason": "native_live_boundary_unverified",
                        "attempt": attempt["attempt_id"],
                    }
                ),
            }
        return self.control.admit(attempt)

    def _case(self, attempt):
        if not isinstance(attempt.get("attempt_id"), str) or not re.fullmatch(
            r"run_[0-9a-f]{64}", attempt["attempt_id"]
        ):
            raise Denied("invalid_attempt")
        return self.root / attempt["attempt_id"]

    def _saved(self, attempt):
        from paired_runner import _generation

        case = self._case(attempt)
        binding = read_private(case / "binding.json")
        if binding.get("attempt_sha256") != sha(attempt):
            raise Denied("attempt_changed")
        value = read_private(case / "generation.json")
        _generation(value, attempt)
        return value, case / "work"

    def normalize(self, text):
        raw = text.encode("utf-8", "strict")
        if len(raw) > MAX_BYTES:
            raise Denied("normalization_overflow")
        result = subprocess.run(
            [str(self.normalizer)],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            timeout=3,
            check=True,
        )
        value = json.loads(result.stdout)
        if set(value) != {"text"} or not isinstance(value["text"], str):
            raise Denied("normalization_unavailable")
        return value["text"]

    def generate(self, attempt, admission):
        if attempt["attempt_id"] in self.generated or admission["status"] != "allowed":
            raise Denied("attempt_unavailable")
        with ExitStack() as cleanup:
            cleanup.callback(self.control.revoke, attempt)
            return self._generate(attempt, admission, cleanup)

    def _generate(self, attempt, admission, cleanup):
        from benchmark_acceptance import contract

        case = self._case(attempt)
        case.mkdir(mode=0o700)
        store_private(
            case / "binding.json",
            {"attempt_sha256": sha(attempt), "admission_sha256": sha(admission)},
        )
        work, launch, runtime, code = (
            case / name for name in ("work", "launch", "runtime", "code")
        )
        for path in (
            work,
            launch,
            runtime / "config",
            runtime / "data",
            runtime / "state",
            runtime / "tmp",
            code,
        ):
            path.mkdir(mode=0o700, parents=True)
        (runtime / "config/config.yaml").write_text("{}\n")
        for name in (
            "protected_mcp.py",
            "harness_mcp.py",
            "factory_harness.py",
            "harness_session.py",
            "harness_evaluation.py",
        ):
            shutil.copyfile(Path(__file__).with_name(name), code / name)
        cancelled = threading.Event()
        deadline = time.monotonic() + 180
        workspace = BoundedWorkspace(work, self.normalize)
        cleanup.callback(workspace.close)
        profile = Profile(
            attempt["profile"],
            attempt["goose_build"],
            attempt["model"],
            attempt["route"],
            "Build the specified project using the authorized typed file tools. Tool discovery never grants authority. Complete all requested files and return a concise result.",
            workspace.tools(),
        )
        broker = Broker(
            profile,
            lambda name, args: self.control.authorize_tool(attempt, name, sha(args)),
            self.normalize,
        )
        if attempt["variant"] == "candidate":
            session = CandidateSession(
                host=self.host,
                broker=broker,
                artifact_root=case / "artifacts",
                attempt=attempt["attempt_id"],
                snapshot=workspace.snapshot,
                deadline=deadline,
                cancelled=cancelled,
            )
            cleanup.callback(session.artifacts.close)
            prefix = profile.prefix()
        else:
            session = BaselineSession(broker, workspace.snapshot, cancelled, deadline)
            prefix = canonical(
                {
                    "version": attempt["profile"],
                    "instructions": profile.instructions,
                    "tools": session.declarations(),
                }
            )
        specification = next(
            t["spec"] for t in self.suite["tasks"] if t["id"] == attempt["task_id"]
        )
        prompt = (
            prefix + "\n\nTASK\n" + specification + "\n" + contract(attempt["task_id"])
        )
        token = secrets.token_hex(32)
        relay = ModelRelay(
            attempt, session, self.control, prompt, token, self.normalize, deadline
        )
        server = RelayServer(("127.0.0.1", 0))
        cleanup.callback(server.server_close)
        server.relay = relay
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cleanup.callback(thread.join, timeout=5)
        cleanup.callback(server.shutdown)
        cleanup.callback(cancelled.set)
        sb = case / "worker.sb"
        sb.write_text(
            seatbelt(
                [work, launch, runtime, code, self.goose],
                [runtime / "data", runtime / "state", runtime / "tmp"],
                server.server_port,
            )
        )
        declaration_sha = sha(session.declarations())
        extension = f"factory:{NATIVE_PYTHON} -I -B {code}/protected_mcp.py --broker-port {server.server_port} --declarations-sha256 {declaration_sha}"
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(runtime),
            "TMPDIR": str(runtime / "tmp"),
            "GOOSE_PATH_ROOT": str(runtime),
            "GOOSE_PROVIDER": "openai",
            "GOOSE_MODEL": "auto",
            "GOOSE_MAX_TOKENS": str(
                self.control.config.get("max_output_tokens", 16384)
            ),
            "OPENAI_HOST": f"http://127.0.0.1:{server.server_port}",
            "OPENAI_BASE_PATH": "v1/chat/completions",
            "OPENAI_API_KEY": token,
            "FACTORY_BROKER_TOKEN": token,
            "GOOSE_DISABLE_SESSION_NAMING": "true",
            "GOOSE_TELEMETRY_ENABLED": "false",
            "GOOSE_MODE": "auto",
            "GOOSE_STATE_MACHINE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        start = time.monotonic()
        probe = run_bounded(
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(sb),
                str(NATIVE_PYTHON),
                "-I",
                "-B",
                "-c",
                "import errno,os,socket,sys\n"
                "for path,flags in [(sys.argv[1],os.O_RDONLY),(sys.argv[2],os.O_WRONLY),(sys.argv[3],os.O_WRONLY|os.O_CREAT)]:\n"
                " try:os.open(path,flags,0o600);raise SystemExit(2)\n except PermissionError:pass\n"
                "s=socket.socket();s.settimeout(.2);raise SystemExit(0 if s.connect_ex(('198.51.100.1',443))==errno.EPERM else 3)",
                str(Path(__file__).with_name("benchmark_acceptance.py").resolve()),
                str(code / "protected_mcp.py"),
                str(work / "unauthorized.py"),
            ],
            cwd=launch,
            env=env,
            timeout=5,
        )
        if probe["exit_code"] != 0 or probe["overflow"] or probe["timed_out"]:
            raise Denied("worker_boundary_unverified")
        result = run_bounded(
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(sb),
                str(self.goose),
                "run",
                "--factory-restricted",
                "--no-profile",
                "--no-session",
                "--max-turns",
                "32",
                "--output-format",
                "stream-json",
                "--with-extension",
                extension,
                "--text",
                prompt,
            ],
            cwd=launch,
            env=env,
            timeout=180,
        )
        # No raw stdout, stderr, prompts or code are written into runner receipts.
        for key in ("stdout", "stderr"):
            result[key] = self.normalize(
                result[key].decode("utf-8", "strict").replace(token, "[REDACTED]")
            )
        diagnostics = result | {
            "relay_failure": relay.failure_reason,
            "closed_provider_calls": len(relay.records),
            "inference_attempts": relay.inference_attempts,
        }
        fd = os.open(
            case / "sanitized-diagnostics.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w") as out:
            out.write(canonical(diagnostics))
        outcome = (
            "completed"
            if result["exit_code"] == 0
            and not result["timed_out"]
            and not result["overflow"]
            and not relay.failed
            and relay.assistant is not None
            and not relay.assistant.get("tool_calls")
            else "failed"
        )
        artifact = workspace.snapshot()
        if not all(
            (work / n).is_file()
            for n in ("solution.py", "README.md", "test_solution.py")
        ):
            outcome = "failed"
        value = {
            "attempt_id": attempt["attempt_id"],
            "artifact_sha256": artifact,
            "dispatch_manifest_sha256": sha(relay.records),
            "call_ids": [r["call_id"] for r in relay.records],
            "elapsed_ms": max(1, int((time.monotonic() - start) * 1000)),
            "generation_receipt_sha256": sha(
                {"artifact": artifact, "calls": relay.records, "outcome": outcome}
            ),
            "model": attempt["model"],
            "route": attempt["route"],
            "goose_build": attempt["goose_build"],
            "profile": attempt["profile"],
            "outcome": outcome,
            "live": False,
        }
        store_private(case / "generation.json", value)
        store_private(
            case / "metrics.json",
            {
                "attempt_id": attempt["attempt_id"],
                "goose_build": attempt["goose_build"],
                "profile": attempt["profile"],
                "route": attempt["route"],
                "model": attempt["model"],
                "calls": relay.metrics,
            },
        )
        self.generated[attempt["attempt_id"]] = (value, work)
        return value

    def evaluate(self, attempt, generation):
        from benchmark_acceptance import evaluate

        saved, work = self._saved(attempt)
        if generation != saved:
            raise Denied("generation_changed")
        workspace = BoundedWorkspace(work, self.normalize)
        try:
            if workspace.snapshot() != saved["artifact_sha256"]:
                raise Denied("artifact_changed")
        finally:
            workspace.close()
        result = evaluate(
            attempt["task_id"],
            saved["artifact_sha256"],
            DockerEvaluator(work, work.parent / "evaluation"),
        )
        # Functional acceptance cannot turn an incomplete/stalled generation into
        # completion. Bind this controller decision to the independent receipt.
        result["accepted"] = result["accepted"] and saved["outcome"] == "completed"
        result["evaluation_receipt_sha256"] = sha(
            {
                "independent_receipt": result["evaluation_receipt_sha256"],
                "generation_outcome": saved["outcome"],
                "accepted": result["accepted"],
            }
        )
        result["evaluator_build"] = sha(
            {
                name: hashlib.sha256(
                    Path(__file__).with_name(name).read_bytes()
                ).hexdigest()
                for name in (
                    "benchmark_acceptance.py",
                    "protected_goose_runtime.py",
                    "container_evaluator.py",
                    "container_eval_host.py",
                    "protected_spending_control.py",
                    "billing_receipts.py",
                    "billing_spending.py",
                )
            }
        )
        return result | {"attempt_id": attempt["attempt_id"]}

    def collect(self, attempt, generation):
        saved, _ = self._saved(attempt)
        if generation != saved:
            raise Denied("generation_changed")
        return self.control.billing(attempt, generation)

    def reconcile(self, attempt, record):
        # The private service must attest dispatch/cancellation and reconcile its
        # retained journal. Local files never establish that a send did not occur.
        value = self.control.reconcile(attempt, record)
        if value.get("status") == "not_dispatched" and self._case(attempt).exists():
            raise Denied("native_launch_reconciliation_required")
        if value.get("generation") is not None:
            saved, _ = self._saved(attempt)
            if value["generation"] != saved:
                raise Denied("generation_changed")
        return value
