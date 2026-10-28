#!/usr/bin/env python3
"""Linux-only network-none fixture: real Goose, factory MCP adapter and execution binary."""
import errno
import http.server
import json
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from goose_factory_boundary_spike import FactoryStub


def main():
    probe = socket.socket()
    probe.settimeout(1)
    assert probe.connect_ex(('198.51.100.1',443)) in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES)
    probe.close()
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),FactoryStub)
    server.records = []
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='goose-mcp-',dir='/work') as root:
            root = Path(root)
            for name in ('allowed','denied_command','masked_nonzero','invalid_utf8','authority_override','outside_write'):
                case = root / name
                work,home,goose,tmp = [case / x for x in ('work','home','goose','tmp')]
                for p in (work,home,goose/'config',goose/'data',goose/'state',tmp): p.mkdir(parents=True)
                (goose/'config/config.yaml').write_text('{}\n')
                policy = case/'policy.toml'
                policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ['+json.dumps(str(work))+']\n')
                scripts = {'allowed':'#!/bin/sh\nprintf executed > executed.marker\nprintf VISIBLE_ALLOWED\n',
                    'dd':'#!/bin/sh\nprintf executed > executed.marker\nprintf VISIBLE_ALLOWED\n',
                    'emit-secret':"#!/bin/sh\nprintf 'sk-OFF'; sleep 0.01; printf 'LINE0123456789ABCDEFGHIJKLMN'; printf 'password=fixture-only' >&2; exit 7\n",
                    'invalid-output':"#!/bin/sh\nprintf benign; printf '\\377' >&2\n"}
                for script,content in scripts.items():
                    p=work/script; p.write_text(content);p.chmod(0o700)
                outside=case/'outside.marker'
                commands={'allowed':{'command':'./allowed'},'denied_command':{'command':'./dd'},
                    'masked_nonzero':{'command':'./emit-secret'},'invalid_utf8':{'command':'./invalid-output'},
                    'authority_override':{'command':'./allowed','cwd':str(work)},
                    'outside_write':{'command':'printf forbidden > '+str(outside)}}
                server.arguments=commands[name]
                offset=len(server.records)
                env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(home),'TMPDIR':str(tmp),
                    'GOOSE_PATH_ROOT':str(goose),'GOOSE_PROVIDER':'openai','GOOSE_MODEL':'gpt-4o-mini',
                    'OPENAI_HOST':'http://127.0.0.1:%s'%server.server_address[1],
                    'OPENAI_BASE_PATH':'v1/chat/completions','OPENAI_API_KEY':'offline-fixture-not-a-credential',
                    'GOOSE_DISABLE_SESSION_NAMING':'true','GOOSE_TELEMETRY_ENABLED':'false',
                    'GOOSE_MODE':'auto','GOOSE_STATE_MACHINE':'0','PYTHONNOUSERSITE':'1'}
                extension='factory:/usr/local/bin/python3 /fixtures/mcp_stdio.py --execution /execution --workdir '+str(work)+' --policy '+str(policy)
                p=subprocess.run(['/goose','run','--no-profile','--no-session','--max-turns','3',
                    '--output-format','stream-json','--with-extension',extension,'--text',
                    'Offline fixture: call the factory tool requested by the provider.','--factory-restricted'],
                    cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
                records=server.records[offset:]
                messages=[m for r in records for m in r['body'].get('messages',[]) if m.get('role')=='tool']
                responses=[json.loads(m['content']) for m in messages]
                expected={'allowed':{'status':'executed','exit_code':0,'stdout':'VISIBLE_ALLOWED','stderr':''},
                    'denied_command':{'status':'refused','reason':'policy_denied'},
                    'masked_nonzero':{'status':'executed','exit_code':7,'stdout':'[REDACTED]','stderr':'[REDACTED]'},
                    'invalid_utf8':{'status':'refused','reason':'output_withheld'},
                    'authority_override':{'status':'refused','reason':'invalid_request'},
                    'outside_write':{'status':'refused','reason':'policy_denied'}}[name]
                assert p.returncode==0 and b'OFFLINE_FACTORY_DONE' in p.stdout, (name,p.returncode,p.stderr.decode(errors='replace')[:500])
                assert len(records)==2 and responses==[expected],(name,len(records),responses)
                assert {t.get('function',{}).get('name') for r in records for t in r['body'].get('tools',[])}=={'factory__shell'}
                assert ((work/'executed.marker').exists())==(name=='allowed') and not outside.exists()
                serialized=json.dumps(records)
                assert 'sk-OFFLINE0123456789ABCDEFGHIJKLMN' not in serialized and 'fixture-only' not in serialized
                print(json.dumps({'case':name,'provider_requests':len(records),'tool_response':responses[0],'pass':True}),flush=True)
            offset=len(server.records)
            bad_extension='factory:/usr/local/bin/python3 /fixtures/mcp_stdio.py --execution /missing --workdir '+str(work)+' --policy '+str(policy)
            failed=subprocess.run(['/goose','run','--no-profile','--no-session','--max-turns','1',
                '--output-format','stream-json','--with-extension',bad_extension,'--text',
                'Offline initialization failure.','--factory-restricted'],cwd=work,env=env,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            assert failed.returncode!=0 and len(server.records)==offset, 'failed MCP initialization reached provider'
            print(json.dumps({'case':'bad_mcp_initialization','provider_requests':0,'pass':True}),flush=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
    print('PASS: Linux network-none Goose to factory MCP and execution tool canaries',flush=True)


if __name__=='__main__': main()
