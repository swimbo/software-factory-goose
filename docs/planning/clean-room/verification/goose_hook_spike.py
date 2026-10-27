#!/usr/bin/env python3
"""Offline v1.49.0 project-hook falsification; never activates factory workers.

Requires the digest-verified Darwin arm64 binary from goose-protocol.md.
The sandbox profile is only this fixture's network/write guard, not the factory
Seatbelt design. All runtime files go into a new temporary directory.
"""
import argparse
import errno
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import threading

BINARY_SHA256 = "6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c"
SANDBOX = "/usr/bin/sandbox-exec"


def execute(argv, cwd, env, timeout=25):
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate(timeout=5)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return {"exit_code": proc.returncode, "timed_out": timed_out,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace")}


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply({"object": "list", "data": [
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "offline-fixture"}]})

    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            self.send_error(413)
            return
        value = json.loads(self.rfile.read(length))
        # Deliberately do not record Authorization or other request headers.
        self.server.records.append({"path": self.path, "body": value})
        usage = {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}
        if value.get("stream"):
            chunks = [
                {"id": "offline-1", "object": "chat.completion.chunk", "created": 1,
                 "model": "gpt-4o-mini", "choices": [{"index": 0, "delta": {
                     "role": "assistant", "content": "OFFLINE_STUB_OK"}, "finish_reason": None}]},
                {"id": "offline-1", "object": "chat.completion.chunk", "created": 1,
                 "model": "gpt-4o-mini", "choices": [{"index": 0, "delta": {},
                     "finish_reason": "stop"}], "usage": usage},
            ]
            body = ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
                    + "data: [DONE]\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.reply({"id": "offline-1", "object": "chat.completion", "created": 1,
                        "model": "gpt-4o-mini", "choices": [{"index": 0, "message": {
                            "role": "assistant", "content": "OFFLINE_STUB_OK"},
                            "finish_reason": "stop"}], "usage": usage})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", required=True, type=Path)
    parser.add_argument("--summary", type=Path,
                        help="Optional new evidence JSON file; refuses overwrite")
    args = parser.parse_args()
    binary = args.goose.resolve()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Requires the audited Darwin arm64 host/binary")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != BINARY_SHA256:
        raise SystemExit("Refusing unaudited executable digest")
    if args.summary and args.summary.exists():
        raise SystemExit("Refusing to overwrite existing evidence")
    root = Path(tempfile.mkdtemp(prefix="sfactory-hook-spike-")).resolve()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    profile = root / "fixture.sb"
    profile.write_text(
        '(version 1)\n(allow default)\n(deny network*)\n'
        '(deny file-write*)\n'
        f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
        f'(allow file-write* (subpath {json.dumps(str(root))}) (literal "/dev/null"))\n'
        f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
    summary = {"binary_sha256": BINARY_SHA256, "root": str(root),
               "scope": "offline project hook only; not factory readiness", "cases": []}
    try:
        base_env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root),
                    "PYTHONNOUSERSITE": "1"}
        # TEST-NET destination is never contacted: require immediate EPERM from
        # Seatbelt before the Goose process can run at all.
        probe = execute([SANDBOX, "-f", str(profile), "/usr/bin/python3", "-c",
                         "import socket,errno; s=socket.socket(); s.settimeout(0.2); "
                         "r=s.connect_ex(('198.51.100.1',443)); print(r); "
                         "raise SystemExit(0 if r==errno.EPERM else 1)"], root, base_env)
        summary["external_network_denied"] = probe["exit_code"] == 0 and probe["stdout"].strip() == str(errno.EPERM)
        if not summary["external_network_denied"]:
            raise RuntimeError("Fixture network guard unverified: " + repr(probe))
        version = execute([SANDBOX, "-f", str(profile), str(binary), "--version"], root, base_env)
        summary["version"] = version["stdout"].strip()
        if version["exit_code"] != 0 or summary["version"] != "1.49.0":
            raise RuntimeError("Pinned binary version check failed")

        for name, install_plugin, disable_plugin in [
                ("baseline_no_plugin", False, False),
                ("project_hook_no_profile", True, False),
                ("disabled_project_hook_control", True, True)]:
            case = root / name
            work = case / "work"
            home = case / "home"
            goose_root = case / "goose"
            for directory in (work, home, goose_root, case / "tmp"):
                directory.mkdir(parents=True)
            marker = work / ".agents/plugins/fixture-hook/hook.marker"
            if install_plugin:
                plugin = marker.parent
                (plugin / "hooks").mkdir(parents=True)
                (plugin / "plugin.json").write_text(json.dumps({
                    "name": "fixture-hook", "version": "0.0.1", "description": "Harmless offline sentinel"}))
                (plugin / "start.sh").write_text(
                    '#!/bin/sh\n/bin/cat >/dev/null\n'
                    'printf "HOOK_EXECUTED\\n" > "$PLUGIN_ROOT/hook.marker"\n')
                (plugin / "hooks/hooks.json").write_text(json.dumps({"hooks": {
                    "SessionStart": [{"hooks": [{"type": "command",
                                                  "command": "sh ${PLUGIN_ROOT}/start.sh"}]}]}}))
            if disable_plugin:
                settings = work / ".config/goose/settings.json"
                settings.parent.mkdir(parents=True)
                settings.write_text(json.dumps({"disabledPlugins": ["fixture-hook"]}))
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home),
                   "TMPDIR": str(case / "tmp"), "GOOSE_PATH_ROOT": str(goose_root),
                   "XDG_CONFIG_HOME": str(home / "config"),
                   "XDG_DATA_HOME": str(home / "data"), "XDG_STATE_HOME": str(home / "state"),
                   "GOOSE_PROVIDER": "openai", "GOOSE_MODEL": "gpt-4o-mini",
                   "OPENAI_HOST": f"http://127.0.0.1:{port}",
                   "OPENAI_BASE_PATH": "v1/chat/completions",
                   "OPENAI_API_KEY": "offline-fixture-not-a-credential",
                   "GOOSE_DISABLE_SESSION_NAMING": "true", "GOOSE_TELEMETRY_ENABLED": "false",
                   "GOOSE_MODE": "auto"}
            before = len(server.records)
            result = execute([SANDBOX, "-f", str(profile), str(binary), "run",
                              "--no-profile", "--no-session", "--max-turns", "1",
                              "--output-format", "json", "--text",
                              "Offline fixture: reply with the provider's fixed text; call no tools."], work, env)
            records = server.records[before:]
            for stream in ("stdout", "stderr"):
                (case / (stream + ".txt")).write_text(result[stream])
            (case / "requests.json").write_text(json.dumps(records, indent=2))
            observed = {"name": name, "exit_code": result["exit_code"],
                        "timed_out": result["timed_out"], "provider_requests": len(records),
                        "provider_paths": [r["path"] for r in records],
                        "advertised_tool_names": sorted({
                            t.get("function", {}).get("name", "unknown")
                            for r in records for t in r["body"].get("tools", [])}),
                        "stub_text_observed": "OFFLINE_STUB_OK" in result["stdout"],
                        "hook_marker": marker.read_text().strip() if marker.exists() else None}
            summary["cases"].append(observed)
        controls = all(c["exit_code"] == 0 and not c["timed_out"]
                       and c["provider_requests"] > 0 and c["stub_text_observed"]
                       for c in summary["cases"])
        by_name = {c["name"]: c for c in summary["cases"]}
        controls = controls and by_name["baseline_no_plugin"]["hook_marker"] is None
        controls = controls and by_name["disabled_project_hook_control"]["hook_marker"] is None
        summary["controls_valid"] = controls
        summary["hypothesis_falsified"] = controls and by_name["project_hook_no_profile"]["hook_marker"] == "HOOK_EXECUTED"
        summary["conclusion"] = (
            "no-profile does not prevent project hook execution" if summary["hypothesis_falsified"]
            else "inconclusive; inspect fixture output, do not infer security")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if args.summary:
        with args.summary.open("x") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("hypothesis_falsified") else 2


if __name__ == "__main__":
    raise SystemExit(main())
