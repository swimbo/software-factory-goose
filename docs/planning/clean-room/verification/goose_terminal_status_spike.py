#!/usr/bin/env python3
"""Pinned Goose headless terminal-status regression, using only a local provider."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import threading
import time
sys.dont_write_bytecode = True
from goose_hook_spike import BINARY_SHA256, SANDBOX, Stub, execute


class TerminalStub(Stub):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            self.send_error(413)
            return
        value = json.loads(self.rfile.read(length))
        self.server.records.append({'path': self.path, 'body': value})
        mode = self.server.mode
        is_summary = 'Please summarize the conversation history provided in the system prompt.' in json.dumps(value)
        recovery = mode in ['recovery_success', 'repeated_context']
        initial_recovery_request = recovery and len(self.server.records) == self.server.case_offset + 1
        error_response = mode in ['provider_error', 'credits', 'compaction', 'proactive_failure', 'manual_compaction_failure'] or (recovery and not is_summary and (initial_recovery_request or mode == 'repeated_context'))
        if error_response:
            body = json.dumps({'error': {'message': 'OFFLINE_PROVIDER_FAILURE', 'type': 'invalid_request_error', 'code': 'context_length_exceeded' if mode in ['compaction', 'recovery_success', 'repeated_context'] else 'fixture_failure'}}).encode()
            self.send_response(402 if mode == 'credits' else 400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.server.seen.set()
            return
        if mode in ['refusal', 'anthropic_success']:
            events = [
                {'type': 'message_start', 'message': {'id': 'fixture', 'role': 'assistant', 'content': [], 'model': 'claude-sonnet-4-5', 'usage': {'input_tokens': 10, 'output_tokens': 0}}},
                {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}},
                {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'OFFLINE_REFUSAL' if mode == 'refusal' else 'OFFLINE_OK'}},
                {'type': 'content_block_stop', 'index': 0},
                {'type': 'message_delta', 'delta': {'stop_reason': 'refusal' if mode == 'refusal' else 'end_turn', 'stop_details': {'explanation': 'OFFLINE_REFUSAL', 'category': 'fixture'}}, 'usage': {'output_tokens': 5}},
                {'type': 'message_stop'},
            ]
            body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in events).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.server.seen.set()
            return
        delta = {'role': 'assistant', 'content': 'OFFLINE_SUMMARY' if recovery and is_summary else ('OFFLINE_OK' if mode in ['success', 'recovery_success'] else 'OFFLINE_PARTIAL')}
        if mode == 'max_turn':
            delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'bounded-missing-tool', 'type': 'function', 'function': {'name': 'offline_nonexistent_tool', 'arguments': '{}'}}]}

        usage = {'prompt_tokens': 10, 'completion_tokens': 4, 'total_tokens': 14}
        if value.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            chunk = {'id': 'fixture', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'gpt-4o-mini',
                     'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]}
            self.wfile.write(('data: ' + json.dumps(chunk) + '\n\n').encode())
            self.wfile.flush()
            self.server.seen.set()
            if mode == 'cancel':
                self.server.release.wait(timeout=15)
                return
            chunk['choices'] = [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls' if mode == 'max_turn' else 'stop'}]
            chunk['usage'] = usage
            self.wfile.write(('data: ' + json.dumps(chunk) + '\n\ndata: [DONE]\n\n').encode())
            self.wfile.flush()
        else:
            self.server.seen.set()
            if mode == 'cancel':
                self.server.release.wait(timeout=15)
                return
            self.reply({'id': 'fixture', 'object': 'chat.completion', 'created': 1, 'model': 'gpt-4o-mini',
                        'choices': [{'index': 0, 'message': delta, 'finish_reason': 'tool_calls' if mode == 'max_turn' else 'stop'}], 'usage': usage})


def json_values(text):
    decoder = json.JSONDecoder()
    values = []
    # The pinned CLI emits a banner even with JSON output. Start only at line boundaries.
    offset = 0
    while offset < len(text):
        start = text.find('{', offset)
        if start == -1:
            break
        if start and text[start - 1] != '\n':
            offset = start + 1
            continue
        try:
            value, size = decoder.raw_decode(text[start:])
            values.append(value)
            offset = start + size
        except ValueError:
            offset = start + 1
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goose', required=True, type=Path)
    parser.add_argument('--sha256', default=BINARY_SHA256)
    parser.add_argument('--expect', choices=['baseline', 'patched'], required=True)
    parser.add_argument('--summary', required=True, type=Path)
    parser.add_argument('--suite', choices=['basic', 'high-risk', 'compaction'], default='basic')
    parser.add_argument('--state-machine', action='store_true')
    parser.add_argument('--factory-restricted', action='store_true')
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit('Refusing overwrite')
    binary = args.goose.resolve()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SystemExit('Requires Darwin arm64 fixture')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.sha256:
        raise SystemExit('Binary digest mismatch')
    root = Path(tempfile.mkdtemp(prefix='sfactory-terminal-status-')).resolve()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TerminalStub)
    server.records = []
    server.seen, server.release = threading.Event(), threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    summary = {'root': str(root), 'binary_sha256': args.sha256, 'expect': args.expect,
               'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'production_worker_enabled': False, 'cases': []}
    modes = ['success', 'provider_error', 'cancel'] if args.suite == 'basic' else ['success', 'credits', 'compaction', 'max_turn', 'anthropic_success', 'refusal']
    if args.suite == 'compaction':
        modes = ['success', 'recovery_success', 'repeated_context', 'proactive_failure']
        if args.state_machine:
            modes.append('manual_compaction_failure')
    summary['suite'] = args.suite
    summary['state_machine'] = args.state_machine
    summary['factory_restricted'] = args.factory_restricted
    try:
        for output_format in ['json', 'stream-json']:
            for mode in modes:
                name = output_format + '_' + mode
                case = root / name
                launch, home, goose_root, tmp = [case / n for n in ['launch', 'home', 'goose', 'tmp']]
                for path in [launch, home, goose_root / 'config', goose_root / 'data', goose_root / 'state', tmp]:
                    path.mkdir(parents=True)
                (goose_root / 'config/config.yaml').write_text('{}\n')
                profile = case / 'fixture.sb'
                profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                    + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                    + '(allow file-write* (literal "/dev/null") '
                    + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [goose_root / 'data', goose_root / 'state', tmp]) + ')\n'
                    + f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
                env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(tmp),
                    'GOOSE_PATH_ROOT': str(goose_root), 'GOOSE_PROVIDER': 'openai', 'GOOSE_MODEL': 'gpt-4o-mini',
                    'OPENAI_HOST': f'http://127.0.0.1:{port}', 'OPENAI_BASE_PATH': 'v1/chat/completions',
                    'OPENAI_API_KEY': 'offline-fixture-not-a-credential', 'GOOSE_DISABLE_SESSION_NAMING': 'true',
                    'GOOSE_TELEMETRY_ENABLED': 'false', 'GOOSE_MODE': 'auto'}
                if args.factory_restricted:
                    env['GOOSE_STATE_MACHINE'] = '0'
                if args.state_machine:
                    env['GOOSE_STATE_MACHINE'] = '1'
                if mode == 'proactive_failure':
                    env['GOOSE_AUTO_COMPACT_THRESHOLD'] = '0.000001'
                if mode in ['refusal', 'anthropic_success']:
                    env.update({'GOOSE_PROVIDER': 'anthropic', 'GOOSE_MODEL': 'claude-sonnet-4-5', 'ANTHROPIC_HOST': f'http://127.0.0.1:{port}', 'ANTHROPIC_API_KEY': 'offline-fixture-not-a-credential'})
                guard = execute([SANDBOX, '-f', str(profile), '/usr/bin/python3', '-c',
                    "import socket,errno;s=socket.socket();s.settimeout(.2);r=s.connect_ex(('198.51.100.1',443));raise SystemExit(0 if r==errno.EPERM else 1)"], launch, env)
                if guard['exit_code'] != 0:
                    raise RuntimeError('External network guard failed')
                if 'version' not in summary:
                    version = execute([SANDBOX, '-f', str(profile), str(binary), '--version'], launch, env)
                    summary['version'] = version['stdout'].strip()
                    if version['exit_code'] != 0 or summary['version'] != '1.49.0':
                        raise RuntimeError('Version mismatch')
                server.mode = mode
                server.seen.clear()
                server.release.clear()
                offset = len(server.records)
                server.case_offset = offset
                child = subprocess.Popen([SANDBOX, '-f', str(profile), str(binary), 'run', '--no-profile', '--no-session',
                    '--max-turns', '1' if mode == 'max_turn' else '9', '--output-format', output_format, '--text', '/compact' if mode == 'manual_compaction_failure' else 'Offline terminal-status fixture.'] + (['--factory-restricted'] if args.factory_restricted else []),
                    cwd=launch, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    if not server.seen.wait(timeout=12):
                        raise RuntimeError('Provider request not observed')
                    if mode == 'cancel':
                        time.sleep(.2)
                        child.send_signal(signal.SIGINT)
                    stdout, stderr = child.communicate(timeout=30)
                finally:
                    server.release.set()
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=5)
                stdout, stderr = stdout.decode(errors='replace'), stderr.decode(errors='replace')
                (case / 'stdout.txt').write_text(stdout)
                (case / 'stderr.txt').write_text(stderr)
                (case / 'requests.json').write_text(json.dumps(server.records[offset:], indent=2) + '\n')
                values = json_values(stdout)
                statuses = [v['metadata'].get('status') for v in values if isinstance(v, dict) and isinstance(v.get('metadata'), dict)]
                event_types = [v.get('type') for v in values if isinstance(v, dict) and 'type' in v]
                completed = 'completed' in statuses or 'complete' in event_types
                failed_status = 'error' in statuses or 'error' in event_types
                positive = child.returncode == 0 and completed and not failed_status and 'OFFLINE_OK' in stdout
                rejected = child.returncode != 0 and not completed and failed_status
                reproduced = child.returncode == 0 and completed
                stimuli = {'cancel': 'OFFLINE_PARTIAL', 'provider_error': 'OFFLINE_PROVIDER_FAILURE',
                    'credits': 'creditsExhausted', 'compaction': 'trying to compact',
                    'max_turn': 'maximum number of actions', 'refusal': 'refused request' if args.state_machine else 'provider refused',
                    'success': 'OFFLINE_OK', 'anthropic_success': 'OFFLINE_OK', 'recovery_success': 'OFFLINE_OK',
                    'repeated_context': 'Context limit still exceeded after compaction' if not args.state_machine else 'OFFLINE_PROVIDER_FAILURE',
                    'proactive_failure': 'trying to compact', 'manual_compaction_failure': 'OFFLINE_PROVIDER_FAILURE'}
                stimulus_visible = stimuli[mode] in stdout
                expected_requests = {'provider_error': 4, 'compaction': 2, 'recovery_success': 3, 'repeated_context': 5 if args.state_machine else 3, 'proactive_failure': 4, 'manual_compaction_failure': 4}.get(mode, 1)
                requests_valid = len(server.records) - offset == expected_requests
                compaction_seen = mode not in ['compaction', 'recovery_success', 'repeated_context', 'proactive_failure', 'manual_compaction_failure'] or any('Please summarize the conversation history provided in the system prompt.' in json.dumps(r['body']) for r in server.records[offset:])
                passed = stimulus_visible and requests_valid and compaction_seen and (positive if mode in ['success', 'anthropic_success', 'recovery_success'] else (reproduced if args.expect == 'baseline' else rejected))
                outcome = {'name': name, 'exit_code': child.returncode, 'metadata_statuses': statuses, 'stream_event_types': event_types,
                    'provider_requests': len(server.records) - offset, 'expected_provider_requests': expected_requests, 'compaction_request_seen': compaction_seen if mode in ['compaction', 'recovery_success', 'repeated_context', 'proactive_failure', 'manual_compaction_failure'] else None, 'external_network_denied': True,
                    'stimulus_visible_in_output': stimulus_visible, 'terminal_failure_rejected': rejected, 'false_success_reproduced': mode not in ['success', 'anthropic_success', 'recovery_success'] and reproduced,
                    'passed': passed, 'requests_sha256': hashlib.sha256((case / 'requests.json').read_bytes()).hexdigest(), 'stdout_sha256': hashlib.sha256(stdout.encode()).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr.encode()).hexdigest()}
                summary['cases'].append(outcome)
                print(json.dumps(outcome), flush=True)
        summary['expectation_met'] = len(summary['cases']) == 2 * len(modes) and all(c['passed'] for c in summary['cases'])
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / 'requests.json').write_text(json.dumps(server.records, indent=2) + '\n')
        with args.summary.open('x') as output:
            json.dump(summary, output, indent=2)
            output.write('\n')
    return 0 if summary.get('expectation_met') else 2


if __name__ == '__main__':
    raise SystemExit(main())
