#!/usr/bin/env python3
"""Offline source-side masking canaries with the real repository Rust masker.

Only synthetic inputs, a pinned Goose binary, a tiny MCP tool, and a loopback
provider are used. Negative controls intentionally expose synthetic strings to
the local recorder. No production masking or runtime integration is changed.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from goose_hook_spike import BINARY_SHA256, SANDBOX, execute
from goose_protected_config_spike import ToolStub

SYNTHETIC = "sk-OFFLINE0123456789ABCDEFGHIJKLMN"
TOOL_SENTINEL = "VISIBLE_TOOL_SENTINEL"
NOTIFICATION_SENTINEL = "VISIBLE_NOTIFICATION_SENTINEL"
MODES = ["raw_success", "chunkwise_success", "masked_success", "raw_tool_error",
         "masked_tool_error", "raw_rpc_error", "masked_rpc_error",
         "raw_notification", "masked_notification"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit("Refusing overwrite")
    binary = args.goose.resolve()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Audited Darwin arm64 host required")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != BINARY_SHA256:
        raise SystemExit("Unexpected Goose binary digest")
    repo = Path(__file__).resolve().parents[4]
    mask_source = repo / "clean-room/crates/execution/src/mask.rs"
    deps = repo / "clean-room/target/debug/deps"
    regexes = sorted(deps.glob("libregex-*.rlib"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not regexes or not shutil.which("rustc"):
        raise SystemExit("Offline Rust compiler/cached regex dependency missing")
    root = Path(tempfile.mkdtemp(prefix="sfactory-mask-boundary-")).resolve()
    shutil.copyfile(mask_source, root / "mask.rs")
    (root / "mask_helper.rs").write_text('''#[path = "mask.rs"] mod mask;
use std::io::{self, Read};
fn main() { let mut s = String::new(); io::stdin().read_to_string(&mut s).unwrap(); print!("{}", mask::mask(&s).text); }
#[cfg(test)] mod boundary_tests {
  use super::mask;
  #[test] fn split_stream_requires_reassembly() {
    let parts = ["sk-OFF", "LINE0123456789ABCDEFGHIJKLMN"];
    assert_eq!(parts.iter().map(|s| mask::mask(s).text).collect::<String>(), parts.join(""));
    assert_eq!(mask::mask(&parts.join("")).text, "[REDACTED]");
  }
}
''')
    compile_base = [shutil.which("rustc"), "--edition=2021", str(root / "mask_helper.rs"),
                    "--extern", "regex=" + str(regexes[0]), "-L", "dependency=" + str(deps)]
    for extra, output in [([], root / "mask_helper"), (["--test"], root / "mask_tests")]:
        subprocess.run(compile_base + extra + ["-o", str(output)], check=True, capture_output=True)
    test_result = subprocess.run([str(root / "mask_tests")], check=True, capture_output=True, text=True)
    (root / "mask-tests.txt").write_text(test_result.stdout)
    summary = {"root": str(root), "binary_sha256": BINARY_SHA256,
               "mask_source_sha256": hashlib.sha256(mask_source.read_bytes()).hexdigest(),
               "mask_helper_sha256": hashlib.sha256((root / "mask_helper").read_bytes()).hexdigest(),
               "rust_tests_passed": "6 passed" in test_result.stdout, "cases": []}
    tool = root / "fixture_mcp.py"
    tool.write_text('''import sys,json,subprocess,time
MODE=sys.argv[1]
HELPER=sys.argv[2]
SECRET="sk-OFFLINE0123456789ABCDEFGHIJKLMN"
def mask(s):
    return subprocess.run([HELPER],input=s,text=True,capture_output=True,check=True,timeout=5).stdout
def reply(value): print(json.dumps(value),flush=True)
for line in sys.stdin:
    req=json.loads(line)
    if 'id' not in req: continue
    method=req.get('method')
    if method=='initialize': result={'protocolVersion':req['params']['protocolVersion'],'capabilities':{'tools':{},'logging':{}},'serverInfo':{'name':'offline-mask-fixture','version':'0.0.1'}}
    elif method=='tools/list': result={'tools':[{'name':'mask_probe','description':'Fixed synthetic masking canary','inputSchema':{'type':'object','properties':{},'additionalProperties':False}}]}
    elif method=='tools/call' and req.get('params',{}).get('name')=='mask_probe':
        # Fake producer emits two chunks. Safe path buffers the bounded fixture
        # record before masking; chunkwise mode is a deliberate negative control.
        parts=[SECRET[:6],SECRET[6:]]
        if MODE=='chunkwise_success': payload=''.join(mask(p) for p in parts)
        elif MODE.startswith('masked'): payload=mask(''.join(parts))
        else: payload=''.join(parts)
        if MODE.endswith('notification'):
            reply({'jsonrpc':'2.0','method':'notifications/message','params':{'level':'info','logger':'fixture','data':'VISIBLE_NOTIFICATION_SENTINEL '+payload}})
            time.sleep(.05)
            result={'content':[{'type':'text','text':'VISIBLE_TOOL_SENTINEL notification sent'}],'isError':False}
        elif MODE.endswith('rpc_error'):
            reply({'jsonrpc':'2.0','id':req['id'],'error':{'code':-32603,'message':'VISIBLE_TOOL_SENTINEL '+payload,'data':{'detail':payload}}});continue
        else:
            result={'content':[{'type':'text','text':'VISIBLE_TOOL_SENTINEL '+payload}],'isError':MODE.endswith('tool_error')}
    elif method in ('ping','logging/setLevel'): result={}
    else:
        reply({'jsonrpc':'2.0','id':req['id'],'error':{'code':-32601,'message':'Unsupported fixture method'}});continue
    reply({'jsonrpc':'2.0','id':req['id'],'result':result})
''')
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ToolStub)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        for mode in MODES:
            case = root / mode
            launch, home, goose_root, tmp = [case / n for n in ("launch", "home", "goose", "tmp")]
            for p in (launch, home, goose_root / "config", goose_root / "data", goose_root / "state", tmp):
                p.mkdir(parents=True)
            (goose_root / "config/config.yaml").write_text("{}\n")
            profile = case / "fixture.sb"
            profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                + '(allow file-write* (literal "/dev/null") '
                + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [goose_root / "data", goose_root / "state", tmp]) + ')\n'
                + f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp),
                "GOOSE_PATH_ROOT": str(goose_root), "GOOSE_PROVIDER": "openai", "GOOSE_MODEL": "gpt-4o-mini",
                "OPENAI_HOST": f"http://127.0.0.1:{port}", "OPENAI_BASE_PATH": "v1/chat/completions",
                "OPENAI_API_KEY": "offline-fixture-not-a-credential", "GOOSE_DISABLE_SESSION_NAMING": "true",
                "GOOSE_TELEMETRY_ENABLED": "false", "GOOSE_MODE": "auto", "PYTHONNOUSERSITE": "1"}
            guard = execute([SANDBOX, "-f", str(profile), "/usr/bin/python3", "-c",
                "import socket,errno;s=socket.socket();s.settimeout(.2);r=s.connect_ex(('198.51.100.1',443));"
                "print(r);raise SystemExit(0 if r==errno.EPERM else 1)"], launch, env)
            if guard["exit_code"] != 0 or guard["stdout"].strip() != "1":
                raise RuntimeError("Network guard unverified")
            if "version" not in summary:
                version = execute([SANDBOX, "-f", str(profile), str(binary), "--version"], launch, env)
                summary["version"] = version["stdout"].strip()
                if version["exit_code"] != 0 or summary["version"] != "1.49.0":
                    raise RuntimeError("Version mismatch")
            offset = len(server.records)
            result = execute([SANDBOX, "-f", str(profile), str(binary), "run", "--no-profile", "--no-session",
                "--max-turns", "3", "--output-format", "stream-json", "--with-extension",
                f"fixture:/usr/bin/python3 {tool} {mode} {root / 'mask_helper'}",
                "--text", "Offline fixture: call the fixed probe."], launch, env)
            records = server.records[offset:]
            captured = json.dumps(records)
            for name, value in [("requests.json", json.dumps(records, indent=2)),
                                ("stdout.txt", result["stdout"]), ("stderr.txt", result["stderr"])]:
                (case / name).write_text(value)
            summary["cases"].append({"mode": mode, "exit_code": result["exit_code"],
                "timed_out": result["timed_out"], "external_network_denied": True,
                "provider_requests": len(records), "stub_completion_observed": "OFFLINE_STUB_OK" in result["stdout"],
                "advertised_tool_names": sorted({t.get("function", {}).get("name", "unknown")
                    for r in records for t in r["body"].get("tools", [])}),
                "tool_sentinel_at_model": TOOL_SENTINEL in captured,
                "raw_synthetic_at_model": SYNTHETIC in captured,
                "redaction_at_model": "[REDACTED]" in captured,
                "notification_sentinel_at_model": NOTIFICATION_SENTINEL in captured,
                "notification_sentinel_in_cli": NOTIFICATION_SENTINEL in result["stdout"] + result["stderr"],
                "raw_synthetic_in_cli": SYNTHETIC in result["stdout"] + result["stderr"],
                "request_capture_sha256": hashlib.sha256((case / "requests.json").read_bytes()).hexdigest()})
        by_mode = {c["mode"]: c for c in summary["cases"]}
        summary["all_tool_paths_exercised"] = all(c["provider_requests"] >= 2 and c["tool_sentinel_at_model"]
            and c["stub_completion_observed"] and c["exit_code"] == 0 and not c["timed_out"] for c in summary["cases"])
        summary["raw_controls_leak_as_expected"] = all(by_mode[m]["raw_synthetic_at_model"]
            for m in ["raw_success", "chunkwise_success", "raw_tool_error", "raw_rpc_error"])
        summary["masked_results_passed"] = all(not by_mode[m]["raw_synthetic_at_model"] and by_mode[m]["redaction_at_model"]
            for m in ["masked_success", "masked_tool_error", "masked_rpc_error"])
        summary["notification_model_path_exercised"] = by_mode["raw_notification"]["notification_sentinel_at_model"]
        summary["notification_cli_path_exercised"] = by_mode["raw_notification"]["notification_sentinel_in_cli"]
        summary["notification_cli_masked"] = by_mode["masked_notification"]["notification_sentinel_in_cli"] and not by_mode["masked_notification"]["raw_synthetic_in_cli"]
        summary["bounded_result"] = summary["all_tool_paths_exercised"] and summary["raw_controls_leak_as_expected"] and summary["masked_results_passed"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        with args.summary.open("x") as f:
            json.dump(summary, f, indent=2)
            f.write("\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("bounded_result") else 2


if __name__ == "__main__":
    raise SystemExit(main())
