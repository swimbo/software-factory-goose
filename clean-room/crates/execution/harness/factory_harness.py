"""Disabled harness candidate. Trusted callers own tools, budget checks and lifetime.

Neither profiles nor scripts confer execution authority. Do not connect this candidate
around the fixed production relay's request matching or atomic spending fences.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import select
import stat
import subprocess
import threading
import time
import uuid

MAX_FRAME = 1024 * 1024
MAX_OUTPUT = 16384
MAX_CALLS = 64


class Denied(Exception):
    """Fixed public failure; never include a tool argument, output or raw exception."""


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    schema: dict
    read_only: bool
    invoke: object

    def declaration(self):
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
        }


class Profile:
    def __init__(self, version, goose_build, model, route, instructions, tools):
        self.version, self.goose_build, self.model, self.route = (
            version,
            goose_build,
            model,
            route,
        )
        self.instructions = instructions
        self.tools = {t.name: t for t in tools}
        if len(self.tools) != len(tools):
            raise Denied("invalid_profile")
        self._prefix = canonical(
            {
                "version": self.version,
                "instructions": self.instructions,
                "tools": ["run_script", "fetch_tool_schema"],
                "available_tools": sorted(self.tools),
                "script_api": "await tools.call(name, arguments); await tools.readBatch([{name, arguments}]); await tools.fetchToolSchema(name); console.log(text); return summary; await mutations in order.",
            }
        )

    def prefix(self):
        return self._prefix

    def discover(self, name):
        if name not in self.tools:
            raise Denied("unknown_tool")
        return canonical(self.tools[name].declaration())

    def messages(self, task):
        return [
            {"role": "system", "content": self.prefix()},
            {"role": "user", "content": task},
        ]


class Broker:
    """Trusted callbacks must complete within the parent's deadline and observe cancel.

    authorize(tool, arguments) must perform the EXISTING atomic authority/accounting
    operation for every invocation, including each read in a batch. Discovery is not
    authorization. Tools remain responsible for path policy, complete text capture,
    cancellation and descendant cleanup. No raw filesystem or shell tool is installed.
    """

    def __init__(self, profile, authorize, normalize):
        self.profile, self.authorize, self.normalize = profile, authorize, normalize
        self.calls = 0
        self.result_bytes = 0
        self.audit = []
        self.lock = threading.Lock()

    def call(self, name, arguments, read_only=False):
        with self.lock:
            tool = self.profile.tools.get(name)
            if (
                tool is None
                or not isinstance(arguments, dict)
                or (read_only and not tool.read_only)
            ):
                raise Denied("unauthorized_tool")
            if self.calls >= MAX_CALLS:
                raise Denied("call_limit")
            self.calls += 1
            if self.authorize(name, arguments) is not True:
                raise Denied("authority_denied")
            self.audit.append({"call": self.calls, "tool": name, "state": "begun"})
            audit = self.audit[-1]
        # Arguments and raw text never enter the audit or exception response.
        try:
            raw = tool.invoke(arguments)
            if not isinstance(raw, str) or len(raw.encode()) > MAX_FRAME:
                raise Denied("output_withheld")
            safe = self.normalize(raw)
            if not isinstance(safe, str):
                raise Denied("output_withheld")
            size = len(safe.encode())
            with self.lock:
                self.result_bytes += size
                if self.result_bytes > MAX_FRAME:
                    raise Denied("output_withheld")
                audit["state"] = "completed"
            return safe
        except Exception:
            audit["state"] = "unknown"
            raise Denied("tool_failed") from None

    def dispatch(self, payload):
        if not isinstance(payload, dict):
            raise Denied("invalid_request")
        if set(payload) == {"schema"}:
            return self.profile.discover(payload["schema"])
        if set(payload) == {"name", "arguments"}:
            return self.call(payload["name"], payload["arguments"])
        if set(payload) == {"reads"}:
            reads = payload["reads"]
            if not isinstance(reads, list) or not 1 <= len(reads) <= 4:
                raise Denied("concurrency_limit")
            for r in reads:
                if (
                    not isinstance(r, dict)
                    or set(r) != {"name", "arguments"}
                    or not isinstance(r["name"], str)
                    or r["name"] not in self.profile.tools
                    or not self.profile.tools[r["name"]].read_only
                    or not isinstance(r["arguments"], dict)
                ):
                    raise Denied("unauthorized_tool")
            with ThreadPoolExecutor(max_workers=4) as pool:
                return list(
                    pool.map(
                        lambda r: self.call(r["name"], r["arguments"], True), reads
                    )
                )
        raise Denied("invalid_request")


class ArtifactStore:
    """Sanitized, quota-bounded text; root must be a trusted private attempt directory."""

    def __init__(self, root, attempt, normalize, limit=MAX_FRAME):
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", attempt)
            or not 0 < limit <= MAX_FRAME
        ):
            raise Denied("invalid_artifact_scope")
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = root.lstat()
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.getuid()
            or st.st_mode & 0o077
        ):
            raise Denied("invalid_artifact_scope")
        self.root, self.attempt, self.normalize, self.limit = (
            root,
            attempt,
            normalize,
            limit,
        )
        self.dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.refs = set()
        self.used = 0

    def close(self):
        if getattr(self, "dirfd", None) is not None:
            os.close(self.dirfd)
            self.dirfd = None

    def __del__(self):
        self.close()

    def put(self, text):
        if self.dirfd is None:
            raise Denied("artifact_denied")
        if not isinstance(text, str) or len(text.encode()) > self.limit:
            raise Denied("output_withheld")
        safe = self.normalize(text)
        data = safe.encode()
        if self.used + len(data) > self.limit:
            raise Denied("output_withheld")
        ref = uuid.uuid4().hex
        fd = os.open(
            ref + ".txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.dirfd,
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except Exception:
            raise Denied("artifact_unavailable") from None
        self.refs.add(ref)
        self.used += len(data)
        return ref

    def page(self, attempt, ref, offset, size):
        if self.dirfd is None:
            raise Denied("artifact_denied")
        if (
            attempt != self.attempt
            or ref not in self.refs
            or type(offset) is not int
            or offset < 0
            or type(size) is not int
            or not 0 < size <= MAX_OUTPUT
        ):
            raise Denied("artifact_denied")
        fd = os.open(
            ref + ".txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dirfd
        )
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.getuid()
                or st.st_nlink != 1
                or st.st_size > self.limit
            ):
                raise Denied("artifact_denied")
            # Offsets are Unicode characters, so pages never split a UTF-8 sequence.
            text = f.read(self.limit + 1).decode("utf-8")
            page = text[offset : offset + size]
            if len(page.encode()) > MAX_OUTPUT:
                raise Denied("output_withheld")
            return page


class StallDetector:
    def __init__(self):
        self.errors = []
        self.states = []
        self.intervened = False
        self.stalled = False
        self.diagnostic_state = None

    def observe(self, workspace, error, mutated):
        if self.stalled:
            return "stalled"
        if self.intervened:
            self.stalled = True
            return "stalled"
        fingerprint = (
            hashlib.sha256(re.sub(r"\s+", " ", error.strip()).encode()).hexdigest()
            if error
            else None
        )
        self.errors = (self.errors + [fingerprint])[-3:] if fingerprint else []
        if mutated:
            self.states = (self.states + [workspace])[-5:]
        oscillating = (
            mutated
            and len(self.states) == 5
            and self.states[0] == self.states[2] == self.states[4]
            and self.states[1] == self.states[3]
            and self.states[0] != self.states[1]
        )
        if (len(self.errors) == 3 and len(set(self.errors)) == 1) or oscillating:
            self.intervened = True
            self.diagnostic_state = workspace
            return "intervene"
        return "continue"


def run_script(host, script, broker, timeout=2.0, cancelled=None):
    """Candidate runner; host is a trusted absolute path, never a script argument.

    This supervisor contains the JS child. Broker callbacks are trusted, bounded
    transports; they must not start uncontained subprocesses or block indefinitely.
    """
    cancelled = cancelled or threading.Event()
    try:
        if isinstance(script, str):
            script.encode("utf-8", "strict")
    except UnicodeError:
        return {"status": "refused", "reason": "invalid_request"}
    if cancelled.is_set():
        return {"status": "refused", "reason": "cancelled"}
    if (
        not isinstance(script, str)
        or len(script.encode()) > 32768
        or not 0 < timeout <= 30
    ):
        return {"status": "refused", "reason": "invalid_request"}
    host = Path(host)
    if not host.is_absolute():
        return {"status": "refused", "reason": "configuration_unavailable"}
    child = None
    selector = selectors.DefaultSelector()
    reason = "execution_unavailable"
    error_fingerprint = None
    try:
        child = subprocess.Popen(
            [str(host)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        os.set_blocking(child.stdin.fileno(), False)

        def send(value):
            data = (canonical(value) + "\n").encode()
            if len(data) > MAX_FRAME:
                raise Denied("output_withheld")
            pending_write = memoryview(data)
            while pending_write:
                if cancelled.is_set() or time.monotonic() >= deadline:
                    raise Denied("cancelled" if cancelled.is_set() else "timed_out")
                if select.select([], [child.stdin.fileno()], [], 0.02)[1]:
                    try:
                        written = os.write(child.stdin.fileno(), pending_write)
                        pending_write = pending_write[written:]
                    except BlockingIOError:
                        continue

        send({"script": script})
        os.set_blocking(child.stdout.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ)
        pending = b""
        output = []
        output_size = 0
        total = 0
        completed = False
        while time.monotonic() < deadline:
            if cancelled.is_set():
                reason = "cancelled"
                break
            events = selector.select(min(0.02, max(0, deadline - time.monotonic())))
            if not events:
                continue
            chunk = os.read(child.stdout.fileno(), 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FRAME:
                raise Denied("output_withheld")
            pending += chunk
            if len(pending) > MAX_FRAME:
                raise Denied("output_withheld")
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                frame = json.loads(line)
                if not isinstance(frame, dict) or completed:
                    raise Denied("invalid_response")
                if set(frame) == {"call"}:
                    reply = broker.dispatch(frame["call"])
                    if cancelled.is_set() or time.monotonic() >= deadline:
                        raise Denied("cancelled" if cancelled.is_set() else "timed_out")
                    send({"value": reply})
                elif set(frame) == {"error"} and isinstance(frame["error"], str):
                    if len(frame["error"].encode()) > 8192:
                        raise Denied("invalid_response")
                    diagnostic = broker.normalize(frame["error"])
                    error_fingerprint = hashlib.sha256(
                        re.sub(r"\s+", " ", diagnostic.strip()).encode()
                    ).hexdigest()
                    raise Denied("javascript_error")
                elif set(frame) == {"output"} and isinstance(frame["output"], str):
                    output_size += len(frame["output"].encode())
                    if output_size > MAX_OUTPUT:
                        raise Denied("output_withheld")
                    output.append(frame["output"])
                elif frame == {"done": True}:
                    completed = True
                else:
                    raise Denied("invalid_response")
        else:
            reason = "timed_out"
        remaining = max(0.01, deadline - time.monotonic())
        if (
            completed
            and not pending
            and not cancelled.is_set()
            and time.monotonic() < deadline
            and child.wait(timeout=remaining) == 0
        ):
            try:
                safe = broker.normalize("".join(output))
                if not isinstance(safe, str):
                    raise Denied("output_withheld")
            except Exception:
                raise Denied("output_withheld") from None
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise Denied("cancelled" if cancelled.is_set() else "timed_out")
            if len(safe.encode()) > MAX_OUTPUT:
                raise Denied("output_withheld")
            return {
                "status": "executed",
                "output": safe,
                "calls": broker.calls,
                "tool_result_bytes": broker.result_bytes,
            }
    except Denied as e:
        reason = str(e)
    except RecursionError:
        reason = "invalid_response"
    except Exception:
        # Never expose raw broker/normalizer/parser exceptions or release partial output.
        pass
    finally:
        selector.close()
        if child:
            # Host cannot fork/exec under its OS policy. Signal owned live leader only.
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            child.stdin.close()
            child.stdout.close()
    response = {"status": "refused", "reason": reason}
    if error_fingerprint is not None:
        response["error_fingerprint"] = error_fingerprint
    return response
