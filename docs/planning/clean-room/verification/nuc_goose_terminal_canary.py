#!/usr/bin/env python3
"""Run only in an owned network-none Linux container with a synthetic local provider."""
import errno
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

from goose_terminal_status_spike import TerminalStub, json_values


def main():
    probe = socket.socket()
    probe.settimeout(1)
    assert probe.connect_ex(('198.51.100.1', 443)) in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES)
    probe.close()
    version = subprocess.check_output(['/goose', '--version'], text=True, timeout=10).strip()
    assert version == '1.49.0', version
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TerminalStub)
    server.records = []
    server.seen, server.release = threading.Event(), threading.Event()
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='goose-canary-', dir='/work') as root:
            root = Path(root)
            for output in ('json', 'stream-json'):
                for mode in ('success', 'provider_error', 'cancel'):
                    case = root / (output + '-' + mode)
                    home, work, goose, tmp = [case / x for x in ('home', 'work', 'goose', 'tmp')]
                    for directory in (home, work, goose / 'config', goose / 'data', goose / 'state', tmp):
                        directory.mkdir(parents=True)
                    (goose / 'config/config.yaml').write_text('{}\n')
                    # Protected project configuration must prevent this inert SessionStart marker.
                    plugin = work / '.agents/plugins/fixture-hook'
                    (plugin / 'hooks').mkdir(parents=True)
                    (plugin / 'plugin.json').write_text(json.dumps({'name':'fixture-hook','version':'0.0.1','description':'offline marker'}))
                    (plugin / 'start.sh').write_text('#!/bin/sh\n/bin/cat >/dev/null\nprintf HOOK > "$PLUGIN_ROOT/hook.marker"\n')
                    (plugin / 'hooks/hooks.json').write_text(json.dumps({'hooks':{'SessionStart':[{'hooks':[{'type':'command','command':'sh ${PLUGIN_ROOT}/start.sh'}]}]}}))
                    settings = work / '.config/goose/settings.json'
                    settings.parent.mkdir(parents=True)
                    settings.write_text(json.dumps({'disabledPlugins':['fixture-hook']}))
                    env = {'PATH':'/usr/bin:/bin', 'HOME':str(home), 'TMPDIR':str(tmp),
                        'GOOSE_PATH_ROOT':str(goose), 'GOOSE_PROVIDER':'openai', 'GOOSE_MODEL':'gpt-4o-mini',
                        'OPENAI_HOST':'http://127.0.0.1:%s' % server.server_address[1],
                        'OPENAI_BASE_PATH':'v1/chat/completions', 'OPENAI_API_KEY':'offline-fixture-not-a-credential',
                        'GOOSE_DISABLE_SESSION_NAMING':'true', 'GOOSE_TELEMETRY_ENABLED':'false',
                        'GOOSE_MODE':'auto', 'GOOSE_STATE_MACHINE':'0'}
                    server.mode = mode
                    server.seen.clear()
                    server.release.clear()
                    offset = len(server.records)
                    server.case_offset = offset
                    child = subprocess.Popen(['/goose','run','--no-profile','--no-session','--max-turns','9',
                        '--output-format',output,'--text','Offline terminal-status fixture.','--factory-restricted'],
                        cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    try:
                        assert server.seen.wait(20), 'local provider not reached'
                        if mode == 'cancel':
                            time.sleep(.2)
                            child.send_signal(signal.SIGINT)
                        stdout, stderr = child.communicate(timeout=45)
                    finally:
                        server.release.set()
                        if child.poll() is None:
                            child.kill()
                            child.communicate(timeout=5)
                    text = stdout.decode(errors='replace')
                    values = json_values(text)
                    statuses = [v['metadata'].get('status') for v in values if isinstance(v, dict) and isinstance(v.get('metadata'),dict)]
                    events = [v.get('type') for v in values if isinstance(v,dict) and 'type' in v]
                    completed = 'completed' in statuses or 'complete' in events
                    failed = 'error' in statuses or 'error' in events
                    ok = child.returncode == 0 and completed and not failed and 'OFFLINE_OK' in text
                    rejected = child.returncode != 0 and not completed and failed
                    expected_requests = 4 if mode == 'provider_error' else 1
                    assert len(server.records)-offset == expected_requests, (output,mode,len(server.records)-offset,stderr.decode(errors='replace')[:300])
                    assert ok if mode == 'success' else rejected, (output,mode,child.returncode,statuses,events,stderr.decode(errors='replace')[:300])
                    assert not (plugin / 'hook.marker').exists(), 'disabled project hook executed'
                    print(json.dumps({'format':output,'case':mode,'exit':child.returncode,'provider_requests':expected_requests,'hook_disabled':True,'pass':True}),flush=True)
            # Current patch deliberately refuses restricted stdio MCP on non-macOS.
            # Confirm the refusal occurs before the synthetic provider is contacted.
            server.mode = 'success'
            offset = len(server.records)
            result = subprocess.run(['/goose','run','--no-profile','--no-session','--max-turns','1',
                '--output-format','stream-json','--with-extension','factory:/usr/bin/false',
                '--text','Offline MCP initialization check.','--factory-restricted'],
                cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            assert result.returncode != 0, 'restricted Linux MCP unexpectedly accepted'
            assert len(server.records) == offset, 'provider reached despite MCP refusal'
            print(json.dumps({'case':'linux_mcp_refused','exit':result.returncode,'provider_requests':0,'pass':True}),flush=True)
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    print('PASS: Linux network-none Goose terminal and protected hook canaries',flush=True)


if __name__ == '__main__':
    main()
