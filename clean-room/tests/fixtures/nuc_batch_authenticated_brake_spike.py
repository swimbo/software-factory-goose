#!/usr/bin/env python3
"""Authenticate and independently stop a disposable two-root batch on the NUC."""
import pathlib, runpy, subprocess, sys
HERE=pathlib.Path(__file__).resolve().parent
old=runpy.run_path(str(HERE/'nuc_authenticated_docker_brake_spike.py'))
base=old['DRIVER'].split("if 'populated 0' not in",1)[0]
tail=r'''
BATCH=__BATCH__; CLEANUP=__BATCH_CLEANUP__
root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-batch-brake-')); runtime=root/'runtime'; runtime.mkdir(mode=0o700); work=root/'source'; work.mkdir()
server=None; batch=None; clients=[]; complete=False
try:
 with tarfile.open(fileobj=io.BytesIO(base64.b64decode(ARCHIVE)),mode='r:gz') as a: a.extractall(work,filter='data')
 env=os.environ.copy(); env['PATH']=str(pathlib.Path.home()/'.cargo/bin')+':'+env.get('PATH',''); env['CARGO_TARGET_DIR']=str(root/'target'); env['CARGO_HOME']=str(root/'cargo'); env['CARGO_BUILD_JOBS']='2'; env['CARGO_PROFILE_DEV_DEBUG']='0'
 dev=root/'dev'; dev.mkdir(); sysroot=root/'sysroot'
 subprocess.run(['apt','download','libssl-dev'],cwd=dev,capture_output=True,check=True,timeout=90)
 packages=list(dev.glob('libssl-dev_*.deb'))
 if len(packages)!=1: raise RuntimeError('development package ambiguous')
 subprocess.run(['dpkg-deb','-x',str(packages[0]),str(sysroot)],check=True,timeout=30)
 lib=sysroot/'usr/lib/x86_64-linux-gnu'
 for name in ('libssl.so.3','libcrypto.so.3'): (lib/name).symlink_to('/usr/lib/x86_64-linux-gnu/'+name)
 env['OPENSSL_LIB_DIR']=str(lib); env['OPENSSL_INCLUDE_DIR']=str(sysroot/'usr/include'); env['CFLAGS']='-I'+str(sysroot/'usr/include/x86_64-linux-gnu')
 build=subprocess.run([str(pathlib.Path.home()/'.cargo/bin/cargo'),'build','--locked','-p','watchdog','--features','fixture','--example','docker_brake_fixture'],cwd=work,env=env,capture_output=True,text=True,timeout=600)
 if build.returncode: raise RuntimeError('fixture build failed: '+build.stderr[-3000:])
 for name,code in [('docker_owner_guardian.py',GUARDIAN),('docker_owned_escape_spike.py',MODULE),('docker_batch_guardian.py',BATCH),('cleanup.py',CLEANUP)]: (runtime/name).write_text(code)
 key=os.urandom(32); (runtime/'brake-key').write_bytes(key); (runtime/'brake-key').chmod(0o444)
 sys.path.insert(0,str(runtime)); from docker_batch_guardian import Batch
 if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker slice already occupied')
 inode=CG.stat().st_ino; token=uuid.uuid4().hex; manifest=runtime/'manifest'; manifest.mkdir(mode=0o700)
 binding=runtime/'brake-binding.json'; binding.write_text(json.dumps({'token':token,'slice':SLICE,'inode':inode})); binding.chmod(0o600)
 batch=Batch(manifest,SLICE,CG)
 for role in ('goose','executor'): batch.prepare_fixed(role,IMAGE,['-u','-c','import time;time.sleep(120)'],['--entrypoint','python3'])
 batch.seal(); ids=[batch.start(role) for role in ('goose','executor')]
 if len(set(ids))!=2 or 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('positive batch control missing')
 sock=runtime/'brake.sock'; server=subprocess.Popen([str(root/'target/debug/examples/docker_brake_fixture'),str(sock),str(runtime),token,TARGET],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
 lines=queue.Queue()
 def reader():
  for line in server.stdout: lines.put(line.strip())
 threading.Thread(target=reader,daemon=True).start()
 if lines.get(timeout=10)!='READY': raise RuntimeError('brake server unavailable')
 def client(uid,keymode,target):
  tok=uuid.uuid4().hex; name='sfactory-brake-client-'+tok; clients.append((name,tok))
  r=docker('run','--rm','--name',name,'--label',CL+'='+tok,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','12','--memory','64m','--cpus','0.5','--user',str(uid)+':'+str(uid),'--mount','type=bind,source='+str(sock)+',target=/brake.sock,readonly','--mount','type=bind,source='+str(runtime/'brake-key')+',target=/key,readonly','--entrypoint','python3','--pull','never',IMAGE,'-u','-c',CLIENT,target,keymode,timeout=15)
  return r.stdout.strip()
 if not client(1003,'valid',TARGET).startswith('HTTP/1.1 403'): raise RuntimeError('wrong UID not denied')
 if not client(1002,'wrong',TARGET).startswith('HTTP/1.1 403'): raise RuntimeError('wrong key not denied')
 if not client(1002,'valid','01ARZ3NDEKTSV4RRFFQ69G5FAW').startswith('HTTP/1.1 409'): raise RuntimeError('unknown target not denied')
 if any(not batch.read(role+'.manifest')['id'] in ids for role in ('goose','executor')) or 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('negative requests changed batch')
 # Hold the actual family lock across an authenticated request. Closure is
 # durable before the cleanup worker can acquire that lock.
 with batch.locked():
  status=client(1002,'valid',TARGET)
  if not status.startswith('HTTP/1.1 503'): raise RuntimeError('busy cleanup did not time out unknown: '+status)
  if not client(1002,'valid',TARGET).startswith('HTTP/1.1 202'): raise RuntimeError('busy cleanup not pending on retry')
  waitfile(manifest/'closed.json',5)
  try: batch.start('goose')
  except (BlockingIOError,RuntimeError): pass
  else: raise RuntimeError('closed batch admitted a start')
 end=time.monotonic()+55
 while True:
  status=client(1002,'valid',TARGET)
  if status.startswith('HTTP/1.1 200'): break
  if not status.startswith('HTTP/1.1 202') or time.monotonic()>=end: raise RuntimeError('authenticated stop unverified: '+status)
  time.sleep(.1)
 for role in ('goose','executor'):
  try: batch.start(role)
  except RuntimeError: pass
  else: raise RuntimeError('closed batch readmitted')
  record=batch.read(role+'.manifest')
  from docker_owner_guardian import DisposableContainer
  owner=DisposableContainer(record['token']); owner.ident=record['id']
  if owner.inspect(record['id']) is not None: raise RuntimeError('owned root remains')
 if CG.stat().st_ino!=inode or 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker empty proof missing')
 print('PASS: UID/key/target denials; authenticated busy stop durably closed admission; both exact roots removed; same worker slice empty',flush=True)
 complete=True
finally:
 if server is not None:
  if server.poll() is None: server.kill()
  server.wait(timeout=5); server.stdout.close()
 errors=[]
 if batch is not None:
  try: batch.stop()
  except Exception as e: errors.append('batch '+str(e))
 for name,tok in clients:
  try:
   r=docker('inspect',name,check=False)
   if r.returncode==0:
    o=json.loads(r.stdout)[0]
    if (o['Config']['Labels'] or {}).get(CL)!=tok: raise RuntimeError('client label mismatch')
    docker('rm','--force',o['Id'])
   elif 'no such object' not in r.stderr.lower(): raise RuntimeError('client state unresolved')
  except Exception as e: errors.append('client '+str(e))
 if complete and not errors:
  import shutil; shutil.rmtree(root)
 else: print('RETAINED '+str(root)+' '+ '; '.join(errors),file=sys.stderr,flush=True)
 if errors: raise RuntimeError('owned cleanup unresolved')
print('LIMIT: fixture authority; no actual relay outage, host/daemon-loss or production identity proof')
'''
script=(base+tail).replace('__ARCHIVE__',repr(__import__('base64').b64encode(old['archive'].getvalue()).decode())).replace('__GUARDIAN__',repr(old['guardian'])).replace('__MODULE__',repr(old['module'])).replace('__SERVICE__',repr('unused')).replace('__CLEANUP__',repr('unused')).replace('__IMAGE__',repr(old['image'])).replace('__BATCH__',repr((HERE/'docker_batch_guardian.py').read_text())).replace('__BATCH_CLEANUP__',repr((HERE/'docker_batch_brake_cleanup.py').read_text()))
if __name__=='__main__':
 result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=720)
 sys.exit(result.returncode)
