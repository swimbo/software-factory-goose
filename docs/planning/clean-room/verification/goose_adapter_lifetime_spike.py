#!/usr/bin/env python3
"""Offline protected adapter lifetime canaries; only owned temporary children.

Exercises direct MCP cancellation/EOF/signals and a real Goose model-bound timeout.
Never enables factory workers or contacts an external provider.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
sys.dont_write_bytecode = True
from goose_factory_boundary_spike import FactoryStub
from goose_hook_spike import BINARY_SHA256, SANDBOX, execute


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.01)
    return False


def running(pid):
    result = subprocess.run(['/bin/ps', '-o', 'stat=', '-p', str(pid)],
                            capture_output=True, text=True, check=False)
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith('Z')


def send(child, value):
    child.stdin.write((json.dumps(value) + '\n').encode())
    child.stdin.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goose', required=True, type=Path)
    parser.add_argument('--execution', required=True, type=Path)
    parser.add_argument('--summary', required=True, type=Path)
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit('Refusing overwrite')
    goose = args.goose.resolve()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SystemExit('Requires audited Darwin arm64 host')
    if hashlib.sha256(goose.read_bytes()).hexdigest() != BINARY_SHA256:
        raise SystemExit('Unexpected Goose digest')
    repo = Path(__file__).resolve().parents[4]
    python = Path(subprocess.check_output(['/usr/bin/xcrun', '--find', 'python3'], text=True).strip()).resolve()
    root = Path(tempfile.mkdtemp(prefix='sfactory-lifetime-')).resolve()
    execution, adapter = root / 'execution', root / 'factory_mcp.py'
    shutil.copyfile(args.execution.resolve(), execution)
    execution.chmod(0o700)
    shutil.copyfile(repo / 'clean-room/crates/execution/adapters/mcp_stdio.py', adapter)
    summary = {'root': str(root), 'production_worker_enabled': False,
               'goose_sha256': BINARY_SHA256, 'python': str(python),
               'execution_sha256': hashlib.sha256(execution.read_bytes()).hexdigest(),
               'adapter_sha256': hashlib.sha256(adapter.read_bytes()).hexdigest(),
               'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'cases': []}
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FactoryStub)
    server.records = []
    server.arguments = {'command': './long-tool'}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        for name in ['positive', 'unrelated_cancel', 'timeout', 'mcp_cancel', 'eof', 'sigterm', 'sigint', 'goose_timeout']:
            case = root / name
            work, launch, home, config, tmp = [case / n for n in ('work', 'launch', 'home', 'goose', 'tmp')]
            for path in [work, launch, home, config / 'config', config / 'data', config / 'state', tmp]:
                path.mkdir(parents=True)
            (config / 'config/config.yaml').write_text('{}\n')
            policy = case / 'policy.toml'
            policy.write_text('blocked_binaries = ["dd"]\nallowed_write_paths = [' + json.dumps(str(work)) + ']\n')
            tool = work / 'long-tool'
            tool.write_text('#!/bin/sh\necho $$ > shell.pid\nprintf partial-output\n(sleep 4; printf survived > late.marker) &\necho $! > descendant.pid\nwait\n')
            tool.chmod(0o700)
            profile = case / 'fixture.sb'
            profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                + '(allow file-write* (literal "/dev/null") '
                + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [work, config / 'data', config / 'state', tmp]) + ')\n'
                + f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(tmp),
                   'GOOSE_PATH_ROOT': str(config), 'GOOSE_PROVIDER': 'openai', 'GOOSE_MODEL': 'gpt-4o-mini',
                   'OPENAI_HOST': f'http://127.0.0.1:{port}', 'OPENAI_BASE_PATH': 'v1/chat/completions',
                   'OPENAI_API_KEY': 'offline-fixture-not-a-credential', 'GOOSE_DISABLE_SESSION_NAMING': 'true',
                   'GOOSE_TELEMETRY_ENABLED': 'false', 'GOOSE_MODE': 'auto', 'PYTHONNOUSERSITE': '1'}
            guard = execute([SANDBOX, '-f', str(profile), '/usr/bin/python3', '-c',
                "import socket,errno;s=socket.socket();s.settimeout(.2);r=s.connect_ex(('198.51.100.1',443));raise SystemExit(0 if r==errno.EPERM else 1)"], launch, env)
            if guard['exit_code'] != 0:
                raise RuntimeError('External network guard failed')
            adapter_cmd = [str(python), str(adapter), '--execution', str(execution), '--workdir', str(work), '--policy', str(policy),
                           '--timeout-secs', '1.5' if name in ('timeout', 'goose_timeout') else '15']
            if name == 'goose_timeout':
                version = execute([SANDBOX, '-f', str(profile), str(goose), '--version'], launch, env)
                if version['exit_code'] != 0 or version['stdout'].strip() != '1.49.0':
                    raise RuntimeError('Goose version mismatch')
                summary['goose_version'] = version['stdout'].strip()
                result = execute([SANDBOX, '-f', str(profile), str(goose), 'run', '--no-profile', '--no-session',
                    '--max-turns', '3', '--output-format', 'stream-json', '--with-extension', 'factory:' + ' '.join(adapter_cmd),
                    '--text', 'Offline lifetime fixture. Call the requested tool.'], launch, env)
                messages = [m for r in server.records for m in r['body'].get('messages', []) if m.get('role') == 'tool']
                response = [json.loads(m['content']) for m in messages]
                time.sleep(4.1)
                outcome = {'name': name, 'provider_requests': len(server.records), 'model_tool_messages': messages,
                           'exit_code': result['exit_code'], 'timed_out': result['timed_out'],
                           'passed': response == [{'status': 'refused', 'reason': 'execution_unavailable'}]
                                     and len(server.records) == 2 and result['exit_code'] == 0 and not result['timed_out']
                                     and 'partial-output' not in json.dumps(server.records)}
            else:
                child = subprocess.Popen([SANDBOX, '-f', str(profile)] + adapter_cmd, cwd=launch, env=env,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    send(child, {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'shell', 'arguments': {'command': './long-tool'}}})
                    if not wait_until(lambda: (work / 'descendant.pid').exists() and (work / 'descendant.pid').stat().st_size > 0):
                        raise RuntimeError('Tool never started')
                    start = time.monotonic()
                    if name in ('mcp_cancel', 'unrelated_cancel'):
                        send(child, {'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': 1 if name == 'mcp_cancel' else '1'}})
                    elif name == 'sigterm':
                        child.send_signal(signal.SIGTERM)
                    elif name == 'sigint':
                        child.send_signal(signal.SIGINT)
                    elif name == 'eof':
                        child.stdin.close()
                        child.stdin = None
                    if name not in ('positive', 'unrelated_cancel'):
                        pids = [int((work / n).read_text()) for n in ['shell.pid', 'descendant.pid']]
                        stopped_promptly = wait_until(lambda: not any(running(pid) for pid in pids), timeout=2.5)
                        stop_latency = round(time.monotonic() - start, 3)
                    else:
                        stopped_promptly, stop_latency = None, None
                    time.sleep(4.3)
                    if name in ('positive', 'unrelated_cancel', 'timeout', 'mcp_cancel'):
                        send(child, {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'})
                        time.sleep(.1)
                    if child.stdin is not None:
                        child.stdin.close()
                        child.stdin = None
                    stdout, stderr = child.communicate(timeout=5)
                    frames = [json.loads(line) for line in stdout.splitlines()]
                    tool_results = [v['result'] for v in frames if v.get('id') == 1]
                    expected = {'status': 'refused', 'reason': 'execution_unavailable'}
                    if name in ('positive', 'unrelated_cancel'):
                        passed = len(tool_results) == 1 and json.loads(tool_results[0]['content'][0]['text']) == {'status': 'executed', 'exit_code': 0, 'stdout': 'partial-output', 'stderr': ''}
                    elif name == 'timeout':
                        passed = len(tool_results) == 1 and tool_results[0]['isError'] and json.loads(tool_results[0]['content'][0]['text']) == expected
                    else:
                        passed = not tool_results and b'partial-output' not in stdout
                    if name in ('positive', 'unrelated_cancel', 'timeout', 'mcp_cancel'):
                        passed = passed and any(v.get('id') == 2 and v.get('result') == {} for v in frames)
                    outcome = {'name': name, 'frames': frames, 'exit_code': child.returncode,
                               'elapsed_seconds': round(time.monotonic() - start, 3), 'stopped_within_2_5_seconds': stopped_promptly,
                               'stop_observed_seconds': stop_latency, 'stderr_empty': not stderr,
                               'passed': passed and child.returncode == 0 and not stderr and stopped_promptly is not False}
                    (case / 'stderr.txt').write_bytes(stderr)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=5)
            pids = [int((work / n).read_text()) for n in ['shell.pid', 'descendant.pid']]
            outcome['recorded_pids_running'] = [pid for pid in pids if running(pid)]
            outcome['late_marker_exists'] = (work / 'late.marker').exists()
            outcome['external_network_denied'] = True
            outcome['passed'] = bool(outcome['passed'] and not outcome['recorded_pids_running']
                                     and outcome['late_marker_exists'] == (name in ('positive', 'unrelated_cancel')))
            summary['cases'].append(outcome)
            print(json.dumps(outcome), flush=True)
        summary['bounded_lifetime_checks_passed'] = all(c['passed'] for c in summary['cases'])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / 'requests.json').write_text(json.dumps(server.records, indent=2) + '\n')
        summary['requests_sha256'] = hashlib.sha256((root / 'requests.json').read_bytes()).hexdigest()
        with args.summary.open('x') as output:
            json.dump(summary, output, indent=2)
            output.write('\n')
    return 0 if summary.get('bounded_lifetime_checks_passed') else 2


if __name__ == '__main__':
    raise SystemExit(main())
