#!/usr/bin/env python3
"""Root-pinned credential-free generic Goose worker. Only its Unix relay is exposed."""

import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

LIMIT = 65536
SOCKET = "/gate/relay.sock"


class WorkerDeadline(Exception):
    pass


class WorkerOverflow(Exception):
    pass


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")),
    )


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def protected(name, maximum):
    fd = os.open("/factory/" + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o444
            or not 0 < info.st_size <= maximum
        ):
            raise ValueError("protected input")
        raw = os.read(fd, maximum + 1)
        if len(raw) != info.st_size:
            raise ValueError("protected input")
        return raw
    finally:
        os.close(fd)


_configuration = None


def profile():
    global _configuration
    if _configuration is not None:
        return _configuration
    value = decode(protected("profile.json", LIMIT))
    if (
        value.get("schema") != 1
        or value.get("purpose") != "sfactory-harness-linux-v1"
        or value.get("worker_uid") != os.geteuid()
        or value.get("broker_uid") == os.geteuid()
    ):
        raise ValueError("profile")
    digest = hashlib.sha256()
    with open("/goose", "rb") as source:
        while raw := source.read(65536):
            digest.update(raw)
    if digest.hexdigest() != value["goose_sha256"]:
        raise ValueError("goose")
    _configuration = value
    return value


def relay(value):
    raw = canonical(value).encode() + b"\n"
    if len(raw) > LIMIT:
        raise ValueError("request")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(35)
        connection.connect(SOCKET)
        if (
            struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )[1]
            != profile()["broker_uid"]
        ):
            raise ValueError("broker peer")
        connection.sendall(raw)
        data = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 1048576:
                raise ValueError("response")
    reply = decode(data)
    if (
        type(reply) is not dict
        or set(reply) != {"ok", "value"}
        or reply["ok"] is not True
    ):
        raise ValueError("reply")
    return reply["value"]


class Shim(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (
                self.path != "/v1/chat/completions"
                or len(lengths) != 1
                or self.headers.get("Transfer-Encoding")
                or not lengths[0].isascii()
                or not lengths[0].isdecimal()
                or not 0 < int(lengths[0]) <= LIMIT
            ):
                raise ValueError("HTTP")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError("HTTP")
            reply = base64.b64decode(
                relay({"type": "inference", "body": decode(raw)}), validate=True
            )
            if len(reply) > 1048576:
                raise ValueError("SSE")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        except Exception:
            self.send_error(502, "protected attempt unavailable")


def mcp():
    configuration = profile()
    while True:
        raw = sys.stdin.buffer.readline(LIMIT + 1)
        if not raw:
            return 0
        if len(raw) > LIMIT or not raw.endswith(b"\n"):
            return 1
        request = decode(raw)
        if "id" not in request:
            continue
        method, params = request.get("method"), request.get("params", {})
        if method == "initialize":
            value = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "factory-generic", "version": "1"},
            }
        elif method == "tools/list":
            declarations = relay({"type": "list"})
            if (
                hashlib.sha256(canonical(declarations).encode()).hexdigest()
                != configuration["declarations_sha256"]
            ):
                raise ValueError("declarations")
            value = {"tools": declarations}
        elif (
            method == "tools/call"
            and type(params) is dict
            and set(params) <= {"name", "arguments", "_meta"}
        ):
            result = relay(
                {
                    "type": "tool",
                    "name": params["name"],
                    "arguments": params["arguments"],
                }
            )
            value = {
                "content": [{"type": "text", "text": canonical(result)}],
                "isError": result.get("status") != "executed",
            }
        elif method == "ping":
            value = {}
        else:
            raise ValueError("MCP")
        print(
            canonical({"jsonrpc": "2.0", "id": request["id"], "result": value}),
            flush=True,
        )
    return 0


def main():
    configuration = profile()
    prompt = protected("prompt.txt", LIMIT)
    if hashlib.sha256(prompt).hexdigest() != configuration["prompt_sha256"]:
        raise ValueError("prompt")
    for name in ("task", "home", "goose/config", "goose/data", "goose/state"):
        Path("/work", name).mkdir(parents=True, exist_ok=True)
    Path("/work/goose/config/config.yaml").write_text("{}\n")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Shim)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(
        PATH="/usr/local/bin:/usr/bin:/bin",
        HOME="/work/home",
        TMPDIR="/work",
        GOOSE_PATH_ROOT="/work/goose",
        GOOSE_PROVIDER="openai",
        GOOSE_MODEL="auto",
        GOOSE_MAX_TOKENS=str(configuration["max_output_tokens"]),
        OPENAI_HOST="http://127.0.0.1:" + str(server.server_port),
        OPENAI_BASE_PATH="v1/chat/completions",
        OPENAI_API_KEY="factory-relay-no-provider-secret",
        GOOSE_DISABLE_SESSION_NAMING="true",
        GOOSE_TELEMETRY_ENABLED="false",
        GOOSE_MODE="auto",
        GOOSE_STATE_MACHINE="0",
        PYTHONDONTWRITEBYTECODE="1",
    )
    process = subprocess.Popen(
        [
            "/goose",
            "run",
            "--factory-restricted",
            "--no-profile",
            "--no-session",
            "--max-turns",
            "32",
            "--output-format",
            "stream-json",
            "--with-extension",
            "factory:/usr/local/bin/python3 -I -B /factory/linux_worker.py --mcp",
            "--text",
            prompt.decode("utf-8"),
        ],
        cwd="/work/task",
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + configuration["max_runtime_ms"] / 1000
    count = 0
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise WorkerDeadline()
            for item, _ in selector.select(
                min(0.1, max(0, deadline - time.monotonic()))
            ):
                raw = os.read(item.fd, 4096)
                if not raw:
                    selector.unregister(item.fileobj)
                count += len(raw)
                if count > 1048576:
                    raise WorkerOverflow()
        return process.wait(timeout=max(0.01, deadline - time.monotonic()))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()
        selector.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    try:
        raise SystemExit(
            mcp() if sys.argv[1:] == ["--mcp"] else main() if not sys.argv[1:] else 1
        )
    except WorkerDeadline:
        raise SystemExit(124)
    except WorkerOverflow:
        raise SystemExit(125)
    except Exception:
        print("protected worker unavailable", file=sys.stderr)
        raise SystemExit(1)
