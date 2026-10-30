#!/usr/bin/env python3
"""Disposable PostgreSQL auth/SQL test, non-root, one random loopback port.

Uses the current OS username in the peer map; this does not prove UID2004 or a
systemd network namespace. Never targets a pre-existing database or service.
"""
import getpass,os,pathlib,socket,subprocess,tempfile
PG=pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17')
FIXTURE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/target/debug/examples/private_genesis_fixture')
env={'PATH':'/usr/bin:/bin','LD_LIBRARY_PATH':str(PG/'lib'),'LANG':'C','HOME':'/tmp'}
def command(*args,check=True):return subprocess.run(list(map(str,args)),env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=check)
with tempfile.TemporaryDirectory(prefix='sfactory-genesis-fixture-',dir='/tmp') as temp:
 root=pathlib.Path(temp);data=root/'data'
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 command(PG/'bin/initdb','-D',data,'-U','sfactory_admin','--auth-local=peer','--auth-host=scram-sha-256','--no-instructions')
 (data/'pg_hba.conf').write_text('local all sfactory_admin peer map=fixture\nhost sfactory sfactory 127.0.0.1/32 trust\nhost all all 127.0.0.1/32 reject\nhost all all ::1/128 reject\n')
 name=getpass.getuser()
 if not name.isascii() or not name.replace('_','').isalnum():raise RuntimeError('unexpected fixture user')
 (data/'pg_ident.conf').write_text('fixture '+name+' sfactory_admin\n')
 running=False
 try:
  command(PG/'bin/pg_ctl','-D',data,'-l',root/'server.log','-o',f'-h 127.0.0.1 -k {root} -p {port}','start');running=True
  command(PG/'bin/createdb','-h',root,'-p',port,'-U','sfactory_admin','sfactory')
  runenv={**env,'SFACTORY_GENESIS_FIXTURE_DIR':str(root),'SFACTORY_GENESIS_FIXTURE_PORT':str(port),'SFACTORY_GENESIS_FIXTURE_APP_TCP':'1'}
  subprocess.run([str(FIXTURE)],env=runenv,capture_output=True,check=True,timeout=30)
  denied=command(PG/'bin/psql','-h','127.0.0.1','-p',port,'-U','sfactory_admin','-d','sfactory','-c','SELECT 1',check=False)
  if denied.returncode==0:raise RuntimeError('TCP admin access unexpectedly allowed')
  allowed=command(PG/'bin/psql','-h','127.0.0.1','-p',port,'-U','sfactory','-d','sfactory','-c','SELECT count(*) FROM outbox',check=False)
  if allowed.returncode!=0:raise RuntimeError('TCP application projection access denied')
  print('PASS: current-user Unix peer mapped admin, denied TCP admin, limited TCP app; disposable cluster')
 finally:
  if running:command(PG/'bin/pg_ctl','-D',data,'-m','immediate','stop')
