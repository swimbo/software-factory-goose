#!/usr/bin/env python3
"""Experimental factory-owned MCP adapter for the protected offline Goose fixture.

Not installed or enabled by the factory. A trusted launcher must protect this
file, the execution binary, policy, argv, and environment. This is not a sandbox.
"""
import argparse
import json
import os
import queue
import signal
import threading
import time
from pathlib import Path
import subprocess
import sys

MAX_FRAME = 65536
MAX_RESPONSE = 16 * 1024 * 1024


def refused(reason):
    return {"status": "refused", "reason": reason}


def valid_response(value):
    if not isinstance(value, dict):
        return False
    if value.get("status") == "refused":
        return set(value) == {"status", "reason"} and value["reason"] in {
            "invalid_request", "configuration_unavailable", "policy_denied",
            "execution_unavailable", "timed_out", "output_withheld"}
    return (set(value) == {"status", "exit_code", "stdout", "stderr"}
            and value["status"] == "executed" and type(value["exit_code"]) is int
            and 0 <= value["exit_code"] <= 255
            and isinstance(value["stdout"], str) and isinstance(value["stderr"], str)
            and len(value["stdout"].encode()) <= 1024 * 1024
            and len(value["stderr"].encode()) <= 1024 * 1024)


def stop_worker(child):
    # The real execution binary handles TERM and kills its separate shell group.
    # Killing only the adapter/worker group cannot reach that shell group.
    if child.poll() is None:
        child.terminate()
    try:
        child.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=2)
    # Never signal a process-group id after communicate has reaped its leader.
    # A non-cooperating worker remains a lifetime gate; a refusal is not cleanup proof.


def run_worker(request, execution, workdir, policy, cancelled, timeout):
    if cancelled.is_set():
        return None
    child = subprocess.Popen([str(execution), "--tool-request"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workdir,
        env={"PATH": "/usr/bin:/bin", "SFACTORY_POLICY": str(policy)}, start_new_session=True)
    deadline = time.monotonic() + timeout
    first = True
    try:
        while True:
            if cancelled.is_set() or time.monotonic() >= deadline:
                return None  # No partial or possibly completed output after cancellation.
            try:
                stdout, stderr = child.communicate(input=request if first else None, timeout=.025)
                if cancelled.is_set() or time.monotonic() >= deadline:
                    return None
                return subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                first = False
    finally:
        stop_worker(child)


def execute_tool(arguments, execution, workdir, policy, cancelled=None, timeout=190):
    if (not isinstance(arguments, dict) or set(arguments) != {"command"}
            or not isinstance(arguments["command"], str)):
        return refused("invalid_request")
    request = json.dumps(arguments).encode()
    if len(request) > MAX_FRAME:
        return refused("invalid_request")
    if not 0 < timeout <= 190:
        return refused("configuration_unavailable")
    cancelled = cancelled if cancelled is not None else threading.Event()
    try:
        result = run_worker(request, execution, workdir, policy, cancelled, timeout)
        # Trusted boundary caps output. Raw stderr is never forwarded.
        if result is None or result.returncode != 0 or len(result.stdout) > MAX_RESPONSE:
            return refused("execution_unavailable")
        value = json.loads(result.stdout)
        return value if valid_response(value) else refused("execution_unavailable")
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError, RecursionError):
        return refused("execution_unavailable")


def tool_result(value):
    return {"content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"))}],
            "isError": value["status"] != "executed" or value["exit_code"] != 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--timeout-secs", type=float, default=190)
    args = parser.parse_args()
    execution, workdir, policy = args.execution.resolve(), args.workdir.resolve(), args.policy.resolve()
    if (not execution.is_file() or not workdir.is_dir() or not policy.is_file()
            or not 0 < args.timeout_secs <= 190):
        raise SystemExit("factory adapter configuration unavailable")
    incoming = queue.Queue(maxsize=16)
    completed = queue.Queue(maxsize=1)
    closing = threading.Event()
    active = None

    def read_frames():
        pending = b""
        while True:
            try:
                chunk = os.read(sys.stdin.fileno(), 4096)
            except OSError:
                incoming.put(None)
                return
            if not chunk:
                incoming.put(None)
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if len(line) + 1 > MAX_FRAME:
                    incoming.put(None)
                    return
                try:
                    request = json.loads(line)
                except (ValueError, UnicodeError, RecursionError):
                    incoming.put(None)
                    return
                if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                    incoming.put(None)
                    return
                if "id" in request and type(request["id"]) not in (int, str):
                    incoming.put(None)
                    return
                incoming.put(request)
            if len(pending) >= MAX_FRAME:
                incoming.put(None)
                return

    def call_tool(request, cancelled):
        try:
            value = execute_tool(request["params"].get("arguments"), execution, workdir,
                                 policy, cancelled, args.timeout_secs)
        except Exception:
            # A worker-thread failure must not strand an active request or expose details.
            value = refused("execution_unavailable")
        completed.put((request["id"], value))

    def write_response(response):
        try:
            print(json.dumps(response, separators=(",", ":")), flush=True)
        except (BrokenPipeError, OSError):
            closing.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _signum, _frame: closing.set())
    threading.Thread(target=read_frames, daemon=True).start()
    while True:
        if closing.is_set():
            if active is None:
                return
            active[1].set()
        try:
            request = incoming.get(timeout=.025)
        except queue.Empty:
            request = {}
        if request is None:
            closing.set()
            if active:
                active[1].set()
            request = {}
        if "id" not in request and request.get("method") == "notifications/cancelled":
            params = request.get("params", {})
            if (active and isinstance(params, dict)
                    and type(params.get("requestId")) is type(active[0])
                    and params.get("requestId") == active[0]):
                active[1].set()
        try:
            request_id, value = completed.get_nowait()
        except queue.Empty:
            pass
        else:
            was_cancelled = active[1].is_set()
            active = None
            # MCP cancellation means the peer no longer wants this result.
            if not closing.is_set() and not was_cancelled:
                write_response({"jsonrpc": "2.0", "id": request_id, "result": tool_result(value)})
        if closing.is_set() or "id" not in request:
            continue
        response = {"jsonrpc": "2.0", "id": request["id"]}
        method = request.get("method")
        params = request.get("params", {})
        if method == "initialize":
            version = params.get("protocolVersion") if isinstance(params, dict) else None
            response["result"] = {"protocolVersion": version if version in {
                "2024-11-05", "2025-03-26", "2025-06-18"} else "2024-11-05",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "factory-shell-fixture", "version": "0.0.1"}}
        elif method == "tools/list":
            response["result"] = {"tools": [{"name": "shell", "description": "Run a policy-checked command in the trusted task directory; output is bounded and masked.",
                "inputSchema": {"type": "object", "properties": {"command": {"type": "string", "maxLength": 16384}},
                                "required": ["command"], "additionalProperties": False}}]}
        elif method == "tools/call" and isinstance(params, dict) and params.get("name") == "shell":
            if active is not None:
                response["error"] = {"code": -32000, "message": "factory adapter busy"}
            else:
                cancelled = threading.Event()
                active = (request["id"], cancelled)
                threading.Thread(target=call_tool, args=(request, cancelled), daemon=False).start()
                continue
        elif method == "ping":
            response["result"] = {}
        else:
            response["error"] = {"code": -32601, "message": "unsupported factory adapter operation"}
        write_response(response)


if __name__ == "__main__":
    main()
