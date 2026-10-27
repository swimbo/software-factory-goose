#!/usr/bin/env python3
"""Fixture-only Goose -> synthetic budget proxy -> synthetic provider; no production gateway."""
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request

import goose_factory_boundary_spike as original

LIMIT = 1_048_576
RESERVATION = 1200  # Synthetic microUSD ceiling for every call, not a provider price.
MAX_SPEND = 750_000
MODEL = 'gpt-4o-mini'
TOOL = {'type': 'function', 'function': {'name': 'factory__shell',
    'description': 'Run a policy-checked command in the trusted task directory; output is bounded and masked.',
    'parameters': {'type': 'object', 'properties': {'command': {'type': 'string', 'maxLength': 16384}},
                   'required': ['command'], 'additionalProperties': False}}}


def valid_request(body):
    if not isinstance(body, dict) or set(body) != {'model','messages','tools','max_tokens','stream','stream_options'}:
        return False
    if body['model'] != MODEL or body['tools'] != [TOOL] or body['max_tokens'] != 16384 or body['stream'] is not True or body['stream_options'] != {'include_usage': True}:
        return False
    messages = body['messages']
    if not isinstance(messages, list) or len(messages) not in (2, 4):
        return False
    for m, role in zip(messages[:2], ('system', 'user')):
        if not isinstance(m, dict) or set(m) != {'role','content'} or m['role'] != role or not isinstance(m['content'], str):
            return False
    if len(messages) == 4:
        assistant, result = messages[2:]
        if not isinstance(assistant, dict) or set(assistant) != {'role','tool_calls','content'} or assistant['role'] != 'assistant' or assistant['content'] is not None:
            return False
        calls = assistant['tool_calls']
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict): return False
        call = calls[0]
        if set(call) != {'id','type','function'} or call['type'] != 'function' or not isinstance(call['id'], str) or not 0 < len(call['id']) <= 128:
            return False
        f = call['function']
        if not isinstance(f, dict) or set(f) != {'name','arguments'} or f['name'] != 'factory__shell' or not isinstance(f['arguments'], str): return False
        try: arguments = json.loads(f['arguments'])
        except ValueError: return False
        # The provider deliberately supplies extra arguments in one negative tool test.
        # Only JSON object framing is checked here; MCP owns the command policy/schema.
        if not isinstance(arguments, dict): return False
        if not isinstance(result, dict) or set(result) != {'role','content','tool_call_id'} or result['role'] != 'tool' or not isinstance(result['content'], str) or result['tool_call_id'] != call['id']:
            return False
    return True


def valid_sse(data):
    try:
        text = data.decode('utf-8')
        events = text.split('\n\n')
        if events[-1] != '' or len(events) != 4 or events[-2] != 'data: [DONE]': return False
        chunks = []
        for event in events[:2]:
            if not event.startswith('data: '): return False
            chunk = json.loads(event[6:])
            if not isinstance(chunk, dict) or chunk.get('object') != 'chat.completion.chunk' or chunk.get('model') != MODEL: return False
            choices = chunk.get('choices')
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0].get('delta'), dict): return False
            chunks.append(choices[0])
        if chunks[0].get('finish_reason') is not None or chunks[1].get('delta') != {}: return False
        delta, finish = chunks[0]['delta'], chunks[1].get('finish_reason')
        if finish == 'stop':
            return set(delta) == {'role','content'} and delta['role'] == 'assistant' and isinstance(delta['content'], str)
        if finish != 'tool_calls' or set(delta) != {'role','tool_calls'} or delta['role'] != 'assistant': return False
        calls = delta['tool_calls']
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict): return False
        call = calls[0]
        if set(call) != {'index','id','type','function'} or call['index'] != 0 or call['type'] != 'function' or not isinstance(call['id'], str) or not 0 < len(call['id']) <= 128: return False
        f = call['function']
        if not isinstance(f, dict) or set(f) != {'name','arguments'} or f['name'] != 'factory__shell' or not isinstance(f['arguments'], str): return False
        return isinstance(json.loads(f['arguments']), dict)
    except (ValueError, UnicodeError, AttributeError, TypeError):
        return False


class Proxy(original.Stub):
    def do_POST(self):
        try:
            if self.path != '/v1/chat/completions': raise ValueError('route')
            raw_len = self.headers.get('Content-Length', '')
            if not raw_len.isdigit() or not 0 < int(raw_len) <= LIMIT: raise ValueError('size')
            raw = self.rfile.read(int(raw_len))
            body = json.loads(raw)
            if not valid_request(body): raise ValueError('shape')
        except (ValueError, UnicodeError):
            self.send_error(400); return
        with self.server.lock:
            if self.server.spent + RESERVATION > MAX_SPEND:
                self.send_error(402); return
            self.server.spent += RESERVATION
            self.server.reservations += 1
        self.server.records.append({'path': self.path, 'body': body})
        # Fixed synthetic fixture only. Goose is Seatbelt-restricted to the proxy port;
        # this proxy alone can reach its separately created loopback upstream.
        self.server.upstream.arguments = self.server.arguments
        req = urllib.request.Request(self.server.upstream_url, data=raw, headers={'Content-Type':'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status != 200: raise ValueError('upstream status')
                data = response.read(LIMIT + 1)
                if len(data) > LIMIT or not valid_sse(data): raise ValueError('upstream body')
        except (OSError, ValueError, urllib.error.URLError):
            self.send_error(502); return  # reservation deliberately retained
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1',0), original.FactoryStub)
    upstream.records = []
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    observed = []
    direct_upstream_denials = []
    execute = original.execute
    def execute_with_upstream_probe(argv, cwd, env, timeout=25):
        if argv[-1].find('198.51.100.1') >= 0:
            code = ("import socket,errno;s=socket.socket();s.settimeout(.2);"
                    "r=s.connect_ex(('127.0.0.1',%d));print(r);"
                    "raise SystemExit(0 if r==errno.EPERM else 1)" % upstream.server_address[1])
            probe = execute([argv[0], '-f', argv[2], '/usr/bin/python3', '-c', code], cwd, env, timeout)
            direct_upstream_denials.append(probe['exit_code'] == 0 and probe['stdout'].strip() == '1')
            if not direct_upstream_denials[-1]: raise RuntimeError('direct upstream denial not verified')
        return execute(argv, cwd, env, timeout)
    original.execute = execute_with_upstream_probe
    old_server = original.http.server.ThreadingHTTPServer
    def server_factory(address, handler):
        server = old_server(address, Proxy)
        server.lock = threading.Lock(); server.spent = 0; server.reservations = 0
        server.upstream = upstream
        server.upstream_url = 'http://127.0.0.1:%d/v1/chat/completions' % upstream.server_address[1]
        observed.append(server)
        return server
    original.http.server.ThreadingHTTPServer = server_factory
    original.FactoryStub = Proxy
    try:
        result = original.main()
        server = observed[0]
        passed = result == 0 and server.reservations == 12 and server.spent == 12 * RESERVATION and len(upstream.records) == 12 and direct_upstream_denials == [True] * 6
        summary_arg = Path(sys.argv[sys.argv.index('--summary') + 1])
        with Path(str(summary_arg) + '.gateway.json').open('x') as f:
            json.dump({'fixture_only': True, 'production_enabled': False, 'upstream_requests': len(upstream.records),
                       'reservations': server.reservations, 'spent_microusd': server.spent,
                       'reservation_microusd_per_call': RESERVATION, 'proxy_only_network_profile': True,
                       'direct_upstream_denials': len(direct_upstream_denials),
                       'six_cases_passed': result == 0, 'passed': passed}, f, indent=2)
            f.write('\n')
        return 0 if passed else 2
    finally:
        upstream.shutdown(); upstream.server_close(); upstream_thread.join(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())
