#!/usr/bin/env python3
"""Exercise the actual execution boundary through protected Goose and factory MCP.

Only a loopback deterministic provider and synthetic local tools are used.
Requires an already-built execution binary. Never starts the factory worker.
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from goose_hook_spike import BINARY_SHA256, SANDBOX, Stub, execute


class FactoryStub(Stub):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            self.send_error(413)
            return
        value = json.loads(self.rfile.read(length))
        self.server.records.append({"path": self.path, "body": value})
        tools = value.get("tools", [])
        has_result = any(m.get("role") == "tool" for m in value.get("messages", []))
        if tools and not has_result:
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "factory-probe",
                "type": "function", "function": {"name": "factory__shell",
                    "arguments": json.dumps(self.server.arguments)}}]}
            finish = "tool_calls"
        else:
            delta = {"role": "assistant", "content": "OFFLINE_FACTORY_DONE"}
            finish = "stop"
        usage = {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}
        if value.get("stream"):
            chunks = [{"id": "offline", "object": "chat.completion.chunk", "created": 1,
                "model": "gpt-4o-mini", "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                {"id": "offline", "object": "chat.completion.chunk", "created": 1,
                 "model": "gpt-4o-mini", "choices": [{"index": 0, "delta": {}, "finish_reason": finish}], "usage": usage}]
            body = ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks) + "data: [DONE]\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            if "tool_calls" in delta:
                delta["tool_calls"][0].pop("index")
            self.reply({"id": "offline", "object": "chat.completion", "created": 1,
                "model": "gpt-4o-mini", "choices": [{"index": 0, "message": delta,
                "finish_reason": finish}], "usage": usage})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--sha256", default=BINARY_SHA256)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--factory-restricted", action="store_true")
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit("Refusing overwrite")
    goose = args.goose.resolve()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Requires audited Darwin arm64 host")
    if hashlib.sha256(goose.read_bytes()).hexdigest() != args.sha256:
        raise SystemExit("Unexpected Goose digest")
    repo = Path(__file__).resolve().parents[4]
    root = Path(tempfile.mkdtemp(prefix="sfactory-real-boundary-")).resolve()
    execution = root / "execution"
    adapter = root / "factory_mcp.py"
    shutil.copyfile(args.execution.resolve(), execution)
    execution.chmod(0o700)
    adapter_source = repo / "clean-room/crates/execution/adapters/mcp_stdio.py"
    shutil.copyfile(adapter_source, adapter)
    summary = {"root": str(root), "goose_sha256": args.sha256,
        "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "execution_sha256": hashlib.sha256(execution.read_bytes()).hexdigest(),
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        "production_worker_enabled": False, "factory_restricted": args.factory_restricted, "cases": []}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FactoryStub)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        for name in ["allowed", "denied_command", "masked_nonzero", "invalid_utf8", "authority_override", "outside_write"]:
            case = root / name
            work, launch, home, goose_root, tmp = [case / n for n in ("work", "launch", "home", "goose", "tmp")]
            for p in (work, launch, home, goose_root / "config", goose_root / "data", goose_root / "state", tmp):
                p.mkdir(parents=True)
            (goose_root / "config/config.yaml").write_text("{}\n")
            policy = case / "policy.toml"
            policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\n'
                              + 'allowed_write_paths = [' + json.dumps(str(work)) + ']\n')
            scripts = {"allowed": "#!/bin/sh\nprintf executed > executed.marker\nprintf VISIBLE_ALLOWED\n",
                "dd": "#!/bin/sh\nprintf executed > executed.marker\nprintf VISIBLE_ALLOWED\n",
                "emit-secret": "#!/bin/sh\nprintf 'sk-OFF'; sleep 0.01; printf 'LINE0123456789ABCDEFGHIJKLMN'; printf 'password=fixture-only' >&2; exit 7\n",
                "invalid-output": "#!/bin/sh\nprintf benign; printf '\\377' >&2\n"}
            for script_name, body in scripts.items():
                path = work / script_name
                path.write_text(body)
                path.chmod(0o700)
            outside = case / "outside.marker"
            commands = {"allowed": {"command": "./allowed"}, "denied_command": {"command": "./dd"},
                "masked_nonzero": {"command": "./emit-secret"}, "invalid_utf8": {"command": "./invalid-output"},
                "authority_override": {"command": "./allowed", "cwd": str(work)},
                "outside_write": {"command": "printf forbidden > " + str(outside)}}
            server.arguments = commands[name]
            profile = case / "fixture.sb"
            profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                + '(allow file-write* (literal "/dev/null") '
                + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [work, goose_root / "data", goose_root / "state", tmp]) + ')\n'
                + f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp),
                "GOOSE_PATH_ROOT": str(goose_root), "GOOSE_PROVIDER": "openai", "GOOSE_MODEL": "gpt-4o-mini",
                "OPENAI_HOST": f"http://127.0.0.1:{port}", "OPENAI_BASE_PATH": "v1/chat/completions",
                "OPENAI_API_KEY": "offline-fixture-not-a-credential", "GOOSE_DISABLE_SESSION_NAMING": "true",
                "GOOSE_TELEMETRY_ENABLED": "false", "GOOSE_MODE": "auto", "PYTHONNOUSERSITE": "1"}
            if args.factory_restricted:
                env["GOOSE_STATE_MACHINE"] = "0"
            guard = execute([SANDBOX, "-f", str(profile), "/usr/bin/python3", "-c",
                "import socket,errno;s=socket.socket();s.settimeout(.2);r=s.connect_ex(('198.51.100.1',443));"
                "print(r);raise SystemExit(0 if r==errno.EPERM else 1)"], launch, env)
            if guard["exit_code"] != 0 or guard["stdout"].strip() != "1":
                raise RuntimeError("Network guard unverified")
            if "version" not in summary:
                version = execute([SANDBOX, "-f", str(profile), str(goose), "--version"], launch, env)
                summary["version"] = version["stdout"].strip()
                if version["exit_code"] != 0 or summary["version"] != "1.49.0":
                    raise RuntimeError("Version mismatch")
            offset = len(server.records)
            extension = f"factory:/usr/bin/python3 {adapter} --execution {execution} --workdir {work} --policy {policy}"
            result = execute([SANDBOX, "-f", str(profile), str(goose), "run", "--no-profile", "--no-session",
                "--max-turns", "3", "--output-format", "stream-json", "--with-extension", extension,
                "--text", "Offline fixture: call the factory tool requested by the provider."] + (["--factory-restricted"] if args.factory_restricted else []), launch, env)
            records = server.records[offset:]
            for filename, value in [("requests.json", json.dumps(records, indent=2)), ("stdout.txt", result["stdout"]), ("stderr.txt", result["stderr"])]:
                (case / filename).write_text(value)
            messages = [m for r in records for m in r["body"].get("messages", []) if m.get("role") == "tool"]
            responses = []
            for message in messages:
                try:
                    responses.append(json.loads(message["content"]))
                except (ValueError, TypeError, KeyError):
                    pass
            summary["cases"].append({"name": name, "exit_code": result["exit_code"], "timed_out": result["timed_out"],
                "external_network_denied": True, "provider_requests": len(records), "tool_messages": messages,
                "boundary_responses": responses, "completion_seen": "OFFLINE_FACTORY_DONE" in result["stdout"],
                "advertised_tool_names": sorted({t.get("function", {}).get("name", "unknown") for r in records for t in r["body"].get("tools", [])}),
                "execution_marker": (work / "executed.marker").read_text() if (work / "executed.marker").exists() else None,
                "outside_marker_exists": outside.exists(),
                "synthetic_key_in_requests": "sk-OFFLINE0123456789ABCDEFGHIJKLMN" in json.dumps(records),
                "synthetic_password_in_requests": "fixture-only" in json.dumps(records),
                "requests_sha256": hashlib.sha256((case / "requests.json").read_bytes()).hexdigest()})
        by_name = {c["name"]: c for c in summary["cases"]}
        summary["controls_valid"] = all(c["exit_code"] == 0 and not c["timed_out"] and c["provider_requests"] == 2
            and c["completion_seen"] and c["advertised_tool_names"] == ["factory__shell"] and len(c["boundary_responses"]) == 1
            for c in summary["cases"])
        expected = {"allowed": {"status": "executed", "exit_code": 0, "stdout": "VISIBLE_ALLOWED", "stderr": ""},
            "denied_command": {"status": "refused", "reason": "policy_denied"},
            "masked_nonzero": {"status": "executed", "exit_code": 7, "stdout": "[REDACTED]", "stderr": "[REDACTED]"},
            "invalid_utf8": {"status": "refused", "reason": "output_withheld"},
            "authority_override": {"status": "refused", "reason": "invalid_request"},
            "outside_write": {"status": "refused", "reason": "policy_denied"}}
        summary["expected_responses_observed"] = all(by_name[n]["boundary_responses"] == [response] for n, response in expected.items())
        summary["markers_correct"] = by_name["allowed"]["execution_marker"] == "executed" and all(
            c["execution_marker"] is None for c in summary["cases"] if c["name"] != "allowed") and not any(c["outside_marker_exists"] for c in summary["cases"])
        summary["synthetic_outputs_absent_from_all_model_requests"] = not any(c["synthetic_key_in_requests"] or c["synthetic_password_in_requests"] for c in summary["cases"])
        summary["bounded_integration_passed"] = all(summary[k] for k in ["controls_valid", "expected_responses_observed", "markers_correct", "synthetic_outputs_absent_from_all_model_requests"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        with args.summary.open("x") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("bounded_integration_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
