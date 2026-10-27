#!/usr/bin/env python3
"""Offline controls for Goose state-machine flag, skill tool and bang dispatch.

This observes a candidate configuration boundary; it does not enable a worker.
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import platform
import sys
import tempfile
import threading
sys.dont_write_bytecode = True
from goose_hook_spike import SANDBOX, Stub, execute

MARKER = 'OFFLINE_SKILL_BODY_92731'


class PathStub(Stub):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            self.send_error(413)
            return
        body = json.loads(self.rfile.read(length))
        self.server.records.append(body)
        has_result = any(m.get('role') == 'tool' for m in body.get('messages', []))
        name = self.server.tool
        if name and not has_result:
            arguments = {'name': 'factory-path-probe'} if name == 'load_skill' else {'source': 'factory-path-probe', 'instructions': 'Return only OFFLINE_DONE.'}
            delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'path-probe', 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}
            finish = 'tool_calls'
        else:
            delta = {'role': 'assistant', 'content': 'OFFLINE_DONE'}
            finish = 'stop'
        chunks = [
            {'id': 'offline', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'gpt-4o-mini', 'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]},
            {'id': 'offline', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'gpt-4o-mini', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}], 'usage': {'prompt_tokens': 10, 'completion_tokens': 4, 'total_tokens': 14}},
        ]
        data = (''.join('data: ' + json.dumps(c) + '\n\n' for c in chunks) + 'data: [DONE]\n\n').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goose', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--factory-restricted', action='store_true')
    parser.add_argument('--interactive-smoke', action='store_true')
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit('Refusing overwrite')
    binary = args.goose.resolve()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or hashlib.sha256(binary.read_bytes()).hexdigest() != args.sha256:
        raise SystemExit('Host or binary mismatch')
    root = Path(tempfile.mkdtemp(prefix='sfactory-execution-path-')).resolve()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), PathStub)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    summary = {'root': str(root), 'binary_sha256': args.sha256, 'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'production_worker_enabled': False, 'cases': []}
    cases = [('legacy_success', '0', None), ('state_machine_success', '1', None),
             ('legacy_skill', '0', 'load_skill'), ('state_machine_skill', '1', 'load_skill'),
             ('legacy_delegate', '0', 'summon__delegate'), ('legacy_bang', '0', None)]
    if args.factory_restricted:
        cases = [('legacy_success', '0', None), ('legacy_skill', '0', 'load_skill'), ('legacy_delegate', '0', 'summon__delegate')] + [(n, f, None) for n, f in [('missing_state', None), ('alternate_state', '1'), ('legacy_bang', '0'), ('slash_command', '0'), ('missing_profile', '0'), ('missing_session', '0'), ('interactive', '0'), ('builtin', '0'), ('recipe', '0'), ('instructions', '0'), ('subrecipe', '0')]]
    if args.interactive_smoke:
        if args.factory_restricted: raise SystemExit('Separate interactive control from factory mode')
        cases = [('interactive_control', '0', None)]
    summary['interactive_smoke'] = args.interactive_smoke
    summary['factory_restricted'] = args.factory_restricted
    try:
        for name, flag, tool in cases:
            case = root / name
            launch, home, goose_root, tmp = [case / n for n in ['launch', 'home', 'goose', 'tmp']]
            for path in [launch, home, goose_root / 'config', goose_root / 'data', goose_root / 'state', tmp]:
                path.mkdir(parents=True)
            (goose_root / 'config/config.yaml').write_text('{}\n')
            skill = launch / '.agents/skills/factory-path-probe/SKILL.md'
            skill.parent.mkdir(parents=True)
            skill.write_text('---\nname: factory-path-probe\ndescription: Harmless offline path fixture.\n---\n' + MARKER + '\n')
            profile = case / 'fixture.sb'
            profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n'
                + f'(deny file-read* (subpath {json.dumps(str(Path.home()))}))\n'
                + '(allow file-write* (literal "/dev/null") '
                + ' '.join(f'(subpath {json.dumps(str(p))})' for p in [goose_root / 'data', goose_root / 'state', tmp]) + ')\n'
                + f'(allow network-outbound (remote tcp "localhost:{port}"))\n')
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(tmp), 'GOOSE_PATH_ROOT': str(goose_root),
                'GOOSE_PROVIDER': 'openai', 'GOOSE_MODEL': 'gpt-4o-mini', 'OPENAI_HOST': f'http://127.0.0.1:{port}',
                'OPENAI_BASE_PATH': 'v1/chat/completions', 'OPENAI_API_KEY': 'offline-fixture-not-a-credential',
                'GOOSE_DISABLE_SESSION_NAMING': 'true', 'GOOSE_TELEMETRY_ENABLED': 'false', 'GOOSE_MODE': 'auto',
                'GOOSE_STATE_MACHINE': flag}
            if flag is None:
                env.pop('GOOSE_STATE_MACHINE')
            guard = execute([SANDBOX, '-f', str(profile), '/usr/bin/python3', '-c', "import socket,errno;s=socket.socket();s.settimeout(.2);raise SystemExit(0 if s.connect_ex(('198.51.100.1',443))==errno.EPERM else 1)"], launch, env)
            if guard['exit_code'] != 0:
                raise RuntimeError('Network guard failed')
            if 'version' not in summary:
                version = execute([SANDBOX, '-f', str(profile), str(binary), '--version'], launch, env)
                summary['version'] = version['stdout'].strip()
                if version['exit_code'] != 0 or summary['version'] != '1.49.0':
                    raise RuntimeError('Version mismatch')
            server.tool = tool
            offset = len(server.records)
            text = '  !printf OFFLINE_BANG' if name == 'legacy_bang' else ('/compact' if name == 'slash_command' else 'Offline path fixture.')
            options = ['--no-profile', '--no-session', '--max-turns', '4', '--output-format', 'stream-json', '--text', text]
            if name == 'interactive_control':
                options += ['--interactive']
            if args.factory_restricted:
                options += ['--factory-restricted']
                if name == 'missing_profile': options.remove('--no-profile')
                if name == 'missing_session': options.remove('--no-session')
                if name == 'interactive': options += ['--interactive']
                if name == 'builtin': options += ['--with-builtin', 'developer']
                if name == 'subrecipe': options += ['--sub-recipe', 'missing-fixture-recipe']
                if name in ['recipe', 'instructions']:
                    options.remove('--text'); options.remove(text)
                    options += ['--' + name, str(case / 'missing-fixture-file')]
            result = execute([SANDBOX, '-f', str(profile), str(binary), 'run'] + options, launch, env)
            records = server.records[offset:]
            for filename, data in [('stdout.txt', result['stdout']), ('stderr.txt', result['stderr']), ('requests.json', json.dumps(records, indent=2))]:
                (case / filename).write_text(data)
            tool_messages = [m for r in records for m in r.get('messages', []) if m.get('role') == 'tool']
            outcome = {'name': name, 'flag': flag, 'exit_code': result['exit_code'], 'timed_out': result['timed_out'],
                'provider_requests': len(records), 'external_network_denied': True,
                'advertised_tools': sorted({t.get('function', {}).get('name', '') for r in records for t in r.get('tools', [])}),
                'tool_messages': tool_messages, 'skill_body_in_tool_result': MARKER in json.dumps(tool_messages),
                'bang_dispatch_seen': 'bang_shell_' in result['stdout'],
                'factory_guard_error': 'factory restricted:' in result['stderr'].lower(),
                'complete_seen': '"type":"complete"' in result['stdout'],
                'session_closed': 'session closed' in result['stdout'],
                'stdout_sha256': hashlib.sha256(result['stdout'].encode()).hexdigest(),
                'requests_sha256': hashlib.sha256((case / 'requests.json').read_bytes()).hexdigest()}
            summary['cases'].append(outcome)
            print(json.dumps(outcome), flush=True)
        by_name = {c['name']: c for c in summary['cases']}
        if args.interactive_smoke:
            c = by_name['interactive_control']
            summary['interactive_initial_prompt_then_eof_passed'] = c['exit_code'] == 0 and c['provider_requests'] == 1 and c['complete_seen'] and c['session_closed'] and not c['timed_out']
            return 0 if summary['interactive_initial_prompt_then_eof_passed'] else 2
        if args.factory_restricted:
            summary['valid_launch_passed'] = by_name['legacy_success']['exit_code'] == 0 and by_name['legacy_success']['provider_requests'] == 1 and by_name['legacy_success']['advertised_tools'] == []
            summary['invalid_launches_rejected_before_provider'] = all(c['exit_code'] != 0 and c['provider_requests'] == 0 and c['factory_guard_error'] and not c['bang_dispatch_seen'] and not c['complete_seen'] for c in summary['cases'] if c['name'] not in ['legacy_success', 'legacy_skill', 'legacy_delegate'])
            summary['unadvertised_calls_rejected'] = all(by_name[n]['provider_requests'] == 2 and 'was not advertised' in json.dumps(by_name[n]['tool_messages']) and not by_name[n]['skill_body_in_tool_result'] for n in ['legacy_skill', 'legacy_delegate'])
            summary['bounded_restriction_passed'] = all(summary[k] for k in ['valid_launch_passed', 'invalid_launches_rejected_before_provider', 'unadvertised_calls_rejected'])
            summary['mandatory_boundary_verified'] = False
            summary['subagent_execution_positive_control'] = 'not_exercised'
            return 0 if summary['bounded_restriction_passed'] else 2
        summary['controls_valid'] = (all(not c['timed_out'] for c in summary['cases'])
            and by_name['legacy_success']['provider_requests'] == 1
            and by_name['legacy_success']['advertised_tools'] == []
            and 'load_skill' in by_name['state_machine_success']['advertised_tools']
            and by_name['state_machine_skill']['skill_body_in_tool_result'])
        summary['legacy_skill_negative_valid'] = (not by_name['legacy_skill']['skill_body_in_tool_result']
            and by_name['legacy_skill']['provider_requests'] == 2 and bool(by_name['legacy_skill']['tool_messages']))
        summary['legacy_delegate_negative_observed'] = (by_name['legacy_delegate']['provider_requests'] == 2
            and bool(by_name['legacy_delegate']['tool_messages']) and by_name['legacy_delegate']['advertised_tools'] == [])
        summary['subagent_execution_positive_control'] = 'not_exercised'
        summary['flag_alone_forces_legacy'] = not by_name['legacy_bang']['bang_dispatch_seen']
        summary['mandatory_boundary_verified'] = False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        args.summary.write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if summary.get('controls_valid') and summary.get('legacy_skill_negative_valid') else 2


if __name__ == '__main__':
    raise SystemExit(main())
