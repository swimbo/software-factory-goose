#!/usr/bin/env python3
"""Run an in-flight fixture tool and escaped session until an external owner kills it."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from goose_factory_boundary_spike import FactoryStub


def main():
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),FactoryStub)
    server.records=[];server.arguments={'command':'./hold'}
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    with tempfile.TemporaryDirectory(prefix='goose-hold-',dir='/work') as root:
        root=Path(root);work,home,goose,tmp=[root/x for x in ('work','home','goose','tmp')]
        for p in (work,home,goose/'config',goose/'data',goose/'state',tmp):p.mkdir(parents=True)
        (goose/'config/config.yaml').write_text('{}\n')
        policy=root/'policy.toml'
        policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ['+json.dumps(str(work))+']\n')
        hold=work/'hold'
        hold.write_text("#!/bin/sh\nsetsid /bin/sh -c 'echo $$ > escaped.pid; exec sleep 120' >/dev/null 2>&1 &\necho ready > active\nexec sleep 120\n")
        hold.chmod(0o700)
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(home),'TMPDIR':str(tmp),
            'GOOSE_PATH_ROOT':str(goose),'GOOSE_PROVIDER':'openai','GOOSE_MODEL':'gpt-4o-mini',
            'OPENAI_HOST':'http://127.0.0.1:%s'%server.server_address[1],
            'OPENAI_BASE_PATH':'v1/chat/completions','OPENAI_API_KEY':'offline-fixture-not-a-credential',
            'GOOSE_DISABLE_SESSION_NAMING':'true','GOOSE_TELEMETRY_ENABLED':'false',
            'GOOSE_MODE':'auto','GOOSE_STATE_MACHINE':'0','PYTHONNOUSERSITE':'1'}
        extension='factory:/usr/local/bin/python3 /fixtures/mcp_stdio.py --execution /execution --workdir '+str(work)+' --policy '+str(policy)
        goose_child=subprocess.Popen(['/goose','run','--no-profile','--no-session','--max-turns','3',
            '--output-format','stream-json','--with-extension',extension,'--text',
            'Offline fixture: call the factory tool requested by the provider.','--factory-restricted'],
            cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        end=time.monotonic()+20
        while time.monotonic()<end:
            if goose_child.poll() is not None:raise RuntimeError('Goose exited before tool became active')
            if (work/'active').exists() and (work/'escaped.pid').exists():break
            time.sleep(.02)
        else:raise RuntimeError('in-flight tool was not observed')
        escaped=int((work/'escaped.pid').read_text())
        assert os.getpgid(escaped)!=os.getpgid(goose_child.pid)
        print('GOOSE_MCP_ACTIVE ESCAPED_PROCESS_GROUP',flush=True)
        time.sleep(120)


if __name__=='__main__':main()
