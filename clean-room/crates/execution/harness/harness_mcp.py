#!/usr/bin/env python3
"""Goose stdio adapter for an already-authorized CandidateSession.

The command-line entrypoint runs only synthetic local fixtures. Production callers
must supply a session bound to the existing protected authority and bounded tools;
there is no production-default registry, provider, credential or shell capability.
"""

import argparse
import json
import http.client
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

# Isolated Python ignores script-directory imports. The launcher protects this directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from factory_harness import Broker, Profile, Tool, canonical
from harness_session import CandidateSession
from harness_evaluation import workspace_hash

MAX_FRAME = 65536


def valid_id(value):
    if type(value) is int:
        return 0 <= value < 2**63
    if type(value) is str:
        try:
            return 0 < len(value.encode("utf-8")) <= 128
        except UnicodeError:
            return False
    return False


def response_for(session, request):
    ident = request.get("id") if isinstance(request, dict) else None
    response = {"jsonrpc": "2.0", "id": ident if valid_id(ident) else None}
    invalid = {"code": -32600, "message": "invalid factory request"}
    if (
        not isinstance(request, dict)
        or request.get("jsonrpc") != "2.0"
        or not valid_id(ident)
        or not isinstance(request.get("method"), str)
    ):
        response["error"] = invalid
        return response
    method, params = request["method"], request.get("params", {})
    if not isinstance(params, dict):
        response["error"] = invalid
    elif method == "initialize":
        version = params.get("protocolVersion")
        response["result"] = {
            "protocolVersion": version
            if version in {"2024-11-05", "2025-03-26", "2025-06-18"}
            else "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "factory-harness-candidate", "version": "1"},
        }
    elif method == "tools/list":
        response["result"] = {"tools": session.declarations()}
    elif (
        method == "tools/call"
        and set(params) in ({"name", "arguments"}, {"name", "arguments", "_meta"})
        and isinstance(params.get("_meta", {}), dict)
        and isinstance(params["name"], str)
    ):
        value = session.call(params["name"], params["arguments"])
        response["result"] = {
            "content": [{"type": "text", "text": canonical(value)}],
            "isError": value.get("status") != "executed",
        }
    elif method == "ping":
        response["result"] = {}
    else:
        response["error"] = {"code": -32601, "message": "unsupported factory operation"}
    return response


def serve(session):
    """Bounded framing, one active call, cancellation/EOF suppress unpublished results."""
    incoming = queue.Queue(maxsize=16)
    completed = queue.Queue(maxsize=1)
    closing = threading.Event()
    active = None
    cancellation_sent = False

    def read_frames():
        pending = b""
        try:
            while not closing.is_set():
                chunk = os.read(sys.stdin.fileno(), 4096)
                if not chunk:
                    closing.set()
                    return
                pending += chunk
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    if len(raw) + 1 > MAX_FRAME:
                        closing.set()
                        return
                    q = json.loads(raw)
                    if not isinstance(q, dict):
                        closing.set()
                        return
                    incoming.put(q)
                if len(pending) >= MAX_FRAME:
                    closing.set()
                    return
        except Exception:
            closing.set()

    def finish_call(q):
        try:
            response = response_for(session, q)
        except Exception:
            response = {
                "jsonrpc": "2.0",
                "id": q["id"],
                "error": {"code": -32000, "message": "factory execution unavailable"},
            }
        completed.put(response)

    def write(response):
        try:
            print(canonical(response), flush=True)
        except (BrokenPipeError, OSError):
            closing.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: closing.set())
    threading.Thread(target=read_frames, daemon=True).start()
    while True:
        if closing.is_set():
            session.cancelled.set()
            if not cancellation_sent:
                cancellation_sent = True
                if hasattr(session, "cancel_remote"):
                    session.cancel_remote()
            if active is None:
                return
        try:
            response = completed.get_nowait()
        except queue.Empty:
            pass
        else:
            if not closing.is_set() and not session.cancelled.is_set():
                write(response)
            active = None
        if closing.is_set():
            if active is None:
                return
            time.sleep(0.01)
            continue
        try:
            request = incoming.get(timeout=0.02)
        except queue.Empty:
            continue
        if "id" not in request:
            if (
                request.get("method") == "notifications/cancelled"
                and active is not None
            ):
                params = request.get("params", {})
                if (
                    isinstance(params, dict)
                    and type(params.get("requestId")) is type(active[0])
                    and params.get("requestId") == active[0]
                ):
                    session.cancelled.set()
                    if not cancellation_sent:
                        cancellation_sent = True
                        if hasattr(session, "cancel_remote"):
                            session.cancel_remote()
            continue
        if request.get("method") == "tools/call" and valid_id(request["id"]):
            if active is not None:
                write(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32000, "message": "factory adapter busy"},
                    }
                )
            else:
                thread = threading.Thread(
                    target=finish_call, args=(request,), daemon=False
                )
                active = (request["id"], thread)
                thread.start()
        else:
            write(response_for(session, request))


def fixture_session(args):
    """Synthetic broker for local canaries, not a general filesystem/tool authority."""
    work = args.worktree.resolve()
    host = args.host.resolve()
    normalizer = args.normalizer.resolve()
    if not work.is_dir() or not host.is_file() or not normalizer.is_file():
        raise ValueError("fixture unavailable")

    def normalize(text):
        result = subprocess.run(
            [str(normalizer)],
            input=text.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=3,
        )
        value = json.loads(result.stdout)
        if set(value) != {"text"} or not isinstance(value["text"], str):
            raise ValueError("normalization unavailable")
        return value["text"]

    def write_marker(arguments):
        if (
            set(arguments) != {"text"}
            or not isinstance(arguments["text"], str)
            or len(arguments["text"].encode()) > 128
        ):
            raise ValueError("invalid fixture")
        # Name is fixed by trusted fixture configuration, never by tool arguments.
        marker = work / "authorized.marker"
        fd = os.open(
            marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w") as output:
            output.write(arguments["text"])
        return "Fixture marker written."

    def read_fixture(arguments):
        if arguments:
            raise ValueError("invalid fixture")
        return "alpha beta"

    def secret_fixture(arguments):
        if arguments:
            raise ValueError("invalid fixture")
        return "sk-OFFLINE0123456789ABCDEFGHIJKLMN"

    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    tools = [
        Tool("fixture_read", "Read fixed synthetic text.", empty, True, read_fixture),
        Tool(
            "fixture_secret",
            "Read synthetic masking control.",
            empty,
            True,
            secret_fixture,
        ),
        Tool(
            "fixture_write",
            "Write one fixed marker.",
            {
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 128}},
                "required": ["text"],
                "additionalProperties": False,
            },
            False,
            write_marker,
        ),
    ]
    profile = Profile(
        "factory-harness-11a-mcp-v1",
        args.goose_sha256,
        "offline-model",
        "offline-loopback-only",
        "Synthetic local canary. No production capability.",
        tools,
    )
    return CandidateSession(
        host=host,
        broker=Broker(profile, lambda *_: True, normalize),
        artifact_root=args.artifacts.resolve(),
        attempt="offline-canary",
        snapshot=lambda: workspace_hash(work),
        deadline=time.monotonic() + 60,
        cancelled=threading.Event(),
    )


class FixtureClient:
    """Synthetic loopback canary only. This is not a production identity transport."""

    def __init__(self, port):
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("fixture unavailable")
        self.port = port
        self.cancelled = threading.Event()

    def _post(self, op, payload, timeout=35):
        data = canonical(payload).encode()
        if len(data) > MAX_FRAME:
            raise ValueError("fixture frame unavailable")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(
                "POST", "/factory/" + op, data, {"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            if (
                response.status != 200
                or response.headers.get_content_type() != "application/json"
            ):
                raise ValueError("fixture response unavailable")
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("fixture response unavailable")
            return json.loads(raw)
        finally:
            conn.close()

    def declarations(self):
        tools = self._post("list", {})
        if (
            not isinstance(tools, list)
            or {t.get("name") for t in tools if isinstance(t, dict)}
            != {"run_script", "fetch_tool_schema"}
            or len(tools) != 2
        ):
            raise ValueError("fixture tools unavailable")
        return tools

    def call(self, name, arguments):
        result = self._post("call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict) or result.get("status") not in {
            "executed",
            "refused",
            "stalled",
            "intervention",
        }:
            raise ValueError("fixture result unavailable")
        return result

    def cancel_remote(self):
        try:
            self._post("cancel", {}, timeout=2)
        except Exception:
            pass  # Unknown transport does not grant authority or release a result.


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--offline-fixture", action="store_true", required=True)
    p.add_argument("--broker-port", type=int, required=True)
    args = p.parse_args()
    serve(FixtureClient(args.broker_port))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(1)
