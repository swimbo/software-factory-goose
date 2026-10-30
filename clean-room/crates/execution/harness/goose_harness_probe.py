#!/usr/bin/env python3
"""Actual pinned Goose/MCP canary with a separate trusted script broker.

Only a synthetic loopback provider is used. Never counts toward the 120 live runs,
registers a production tool, reads a key, or changes the gateway/host services.
"""

import argparse
import hashlib
import http.server
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace

from factory_harness import canonical
from harness_mcp import fixture_session

GOOSE_SHA256 = "512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb"


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, value):
        raw = canonical(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(
            {
                "object": "list",
                "data": [
                    {
                        "id": "gpt-4o-mini",
                        "object": "model",
                        "owned_by": "synthetic-canary",
                    }
                ],
            }
        )

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 65536:
                self.send_error(413)
                return
            value = json.loads(self.rfile.read(size))
            if self.path == "/factory/list" and value == {}:
                self.reply(self.server.session.declarations())
                return
            if self.path == "/factory/cancel" and value == {}:
                self.server.session.cancelled.set()
                self.reply({"cancelled": True})
                return
            if (
                self.path == "/factory/call"
                and isinstance(value, dict)
                and set(value) == {"name", "arguments"}
            ):
                self.reply(self.server.session.call(value["name"], value["arguments"]))
                return
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            self.server.records.append(value)
            if len(self.server.records) > 2:
                self.send_error(409)
                return
            finished = any(m.get("role") == "tool" for m in value.get("messages", []))
            if not finished:
                delta = {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "canary-call",
                            "type": "function",
                            "function": {
                                "name": "factory__" + self.server.operation,
                                "arguments": canonical(self.server.arguments),
                            },
                        }
                    ],
                }
                reason = "tool_calls"
            else:
                delta = {"role": "assistant", "content": "SYNTHETIC_CANARY_DONE"}
                reason = "stop"
            chunks = [
                {
                    "id": "canary",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-4o-mini",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                },
                {
                    "id": "canary",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-4o-mini",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 4,
                        "total_tokens": 14,
                    },
                },
            ]
            raw = (
                "".join("data: " + canonical(c) + "\n\n" for c in chunks)
                + "data: [DONE]\n\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except Exception:
            self.send_error(502)


def run(args):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("requires audited Darwin ARM64 fixture host")
    binary = args.goose.resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest() != GOOSE_SHA256:
        raise RuntimeError("unaudited Goose build")
    if args.summary.exists():
        raise RuntimeError("refusing evidence overwrite")
    root = Path(tempfile.mkdtemp(prefix="sfactory-harness-goose-")).resolve()
    code = root / "protected"
    code.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    for name in [
        "harness_mcp.py",
        "factory_harness.py",
        "harness_session.py",
        "harness_evaluation.py",
    ]:
        shutil.copyfile(source / name, code / name)
    for name, original in [
        ("script-host", args.host.resolve()),
        ("normalizer", args.normalizer.resolve()),
    ]:
        shutil.copyfile(original, code / name)
        (code / name).chmod(0o700)
    sys.path.insert(0, str(source.parents[3] / "docs/planning/clean-room/verification"))
    # Existing bounded-duration synthetic Goose helper; no new production supervisor.
    from goose_hook_spike import execute

    cases = [
        (
            "allowed",
            "run_script",
            {
                "script": 'const xs=await tools.readBatch([{name:"fixture_read",arguments:{}}]);await tools.call("fixture_write",{text:"AUTHORIZED"});return xs[0].split(" ")[0];'
            },
            "executed",
        ),
        (
            "unknown_tool",
            "run_script",
            {"script": 'return await tools.call("not_authorized",{});'},
            "refused",
        ),
        (
            "masked",
            "run_script",
            {"script": 'return await tools.call("fixture_secret",{});'},
            "executed",
        ),
        (
            "authority_override",
            "run_script",
            {
                "script": 'return await tools.call("fixture_write",{text:"DENIED"});',
                "workdir": "/",
            },
            "refused",
        ),
        (
            "outside_write",
            "run_script",
            {
                "script": 'return await tools.call("fixture_write",{text:"DENIED",path:"/outside"});'
            },
            "refused",
        ),
        ("schema_discovery", "fetch_tool_schema", {"name": "fixture_read"}, "executed"),
    ]
    summary = {
        "version": 1,
        "synthetic": True,
        "goose_sha256": GOOSE_SHA256,
        "candidate_enabled": False,
        "production_registered": False,
        "live_benchmark_runs": 0,
        "root": str(root),
        "cases": [],
    }
    for name, operation, arguments, expected in cases:
        case = root / name
        case.mkdir(mode=0o700)
        work, launch, home, runtime, artifacts = [
            case / p for p in ["work", "launch", "home", "runtime", "artifacts"]
        ]
        for directory in [
            work,
            launch,
            home,
            runtime / "config",
            runtime / "data",
            runtime / "state",
            case / "tmp",
            artifacts,
        ]:
            directory.mkdir(parents=True, mode=0o700)
        subprocess.run(["git", "init", "-q", str(work)], check=True)
        (runtime / "config/config.yaml").write_text("{}\n")
        session = fixture_session(
            SimpleNamespace(
                worktree=work,
                host=code / "script-host",
                normalizer=code / "normalizer",
                artifacts=artifacts,
                goose_sha256=GOOSE_SHA256,
            )
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        server.session, server.records, server.operation, server.arguments = (
            session,
            [],
            operation,
            arguments,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_port
        profile = case / "fixture.sb"
        # Trusted broker lives outside this worker profile; code/config are read-only.
        profile.write_text(
            "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n"
            + f"(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n"
            + '(allow file-write* (literal "/dev/null") '
            + " ".join(
                f"(subpath {json.dumps(str(p))})"
                for p in [work, runtime / "data", runtime / "state", case / "tmp"]
            )
            + ")\n"
            + f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": str(case / "tmp"),
            "GOOSE_PATH_ROOT": str(runtime),
            "GOOSE_PROVIDER": "openai",
            "GOOSE_MODEL": "gpt-4o-mini",
            "OPENAI_HOST": f"http://127.0.0.1:{port}",
            "OPENAI_BASE_PATH": "v1/chat/completions",
            "OPENAI_API_KEY": "synthetic-placeholder-not-a-key",
            "GOOSE_DISABLE_SESSION_NAMING": "true",
            "GOOSE_TELEMETRY_ENABLED": "false",
            "GOOSE_MODE": "auto",
            "GOOSE_STATE_MACHINE": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            guard = execute(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(profile),
                    "/usr/bin/python3",
                    "-c",
                    'import socket,errno;s=socket.socket();s.settimeout(.2);raise SystemExit(0 if s.connect_ex(("198.51.100.1",443))==errno.EPERM else 1)',
                ],
                launch,
                env,
            )
            if guard["exit_code"] != 0:
                raise RuntimeError("network guard failed")
            protected = execute(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(profile),
                    "/usr/bin/python3",
                    "-c",
                    "import os,sys;\ntry:os.open(sys.argv[1],os.O_WRONLY);raise SystemExit(1)\nexcept PermissionError:pass",
                    str(code / "harness_mcp.py"),
                ],
                launch,
                env,
            )
            if protected["exit_code"] != 0:
                raise RuntimeError("protected adapter write guard failed")
            extension = f"factory:/usr/bin/python3 -I -B {code}/harness_mcp.py --offline-fixture --broker-port {port}"
            result = execute(
                [
                    "/usr/bin/sandbox-exec",
                    "-f",
                    str(profile),
                    str(binary),
                    "run",
                    "--factory-restricted",
                    "--no-profile",
                    "--no-session",
                    "--max-turns",
                    "3",
                    "--output-format",
                    "stream-json",
                    "--with-extension",
                    extension,
                    "--text",
                    session.profile.prefix(),
                ],
                launch,
                env,
            )
            messages = [
                m
                for record in server.records
                for m in record.get("messages", [])
                if m.get("role") == "tool"
            ]
            values = []
            for message in messages:
                try:
                    values.append(json.loads(message["content"]))
                except (ValueError, TypeError):
                    values.append({"status":"unparsed"})
            (case / "protocol-diagnostics.json").write_text(canonical({"tool_messages":messages,"stderr":result["stderr"]}))
            advertised = sorted(
                {
                    t["function"]["name"]
                    for record in server.records
                    for t in record.get("tools", [])
                }
            )
            text = canonical(server.records)
            observed = {
                "name": name,
                "exit_code": result["exit_code"],
                "timed_out": result["timed_out"],
                "provider_calls": len(server.records),
                "tool_statuses": [v.get("status") for v in values],
                "marker": (work / "authorized.marker").read_text()
                if (work / "authorized.marker").exists()
                else None,
                "two_core_tools_only": advertised
                == ["factory__fetch_tool_schema", "factory__run_script"],
                "secret_absent": "sk-OFFLINE0123456789ABCDEFGHIJKLMN" not in text,
                "masked_result_observed": any(
                    "[REDACTED]" in canonical(v) for v in values
                ),
                "external_network_denied": True,
                "protected_code_write_denied": True,
                "request_sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
            observed["passed"] = (
                observed["exit_code"] == 0
                and not observed["timed_out"]
                and observed["provider_calls"] == 2
                and observed["tool_statuses"] == [expected]
                and observed["two_core_tools_only"]
                and observed["secret_absent"]
                and observed["marker"] == ("AUTHORIZED" if name == "allowed" else None)
                and (name != "masked" or observed["masked_result_observed"])
            )
            summary["cases"].append(observed)
            (case / "diagnostics.json").write_text(
                canonical({"stdout": result["stdout"], "stderr": result["stderr"]})
            )
        finally:
            session.cancelled.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
    summary["passed"] = (
        all(x["passed"] for x in summary["cases"]) and len(summary["cases"]) == 6
    )
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.summary.open("x") as output:
        output.write(canonical(summary) + "\n")
    print(canonical(summary))
    return 0 if summary["passed"] else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("goose", "host", "normalizer", "summary"):
        p.add_argument("--" + name, type=Path, required=True)
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
