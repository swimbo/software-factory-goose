#!/usr/bin/env python3
"""Isolated NUC fixture: Rust peer-authenticated brake against owned Docker worker."""
import base64, io, pathlib, subprocess, sys, tarfile
HERE=pathlib.Path(__file__).resolve().parent
CRATE=HERE.parent.parent
archive=io.BytesIO()
with tarfile.open(fileobj=archive,mode='w:gz') as t:
 for name in ('Cargo.toml','Cargo.lock','crates'): t.add(CRATE/name,arcname=name)
source=(HERE/'nuc_docker_slice_spike.py').read_text(); ns={}
exec(source[source.index('ESCAPE='):source.index('\ndef run(')],ns)
recovery={}
recovery_source=(HERE/'nuc_systemd_docker_recovery_spike.py').read_text()
exec(recovery_source[recovery_source.index('SERVICE='):recovery_source.index('DRIVER=')],recovery)
guardian=(HERE/'docker_owner_guardian.py').read_text()
image='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
module='IMAGE='+repr(image)+'\nLABEL='+repr('org.software-factory.escape-spike')+'\nMAIN='+repr(ns['MAIN'])+'\n'
DRIVER=r'''import base64,io,json,os,pathlib,queue,subprocess,sys,tarfile,tempfile,threading,time,uuid
PARENT='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'; SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'; CG=pathlib.Path('/sys/fs/cgroup')/PARENT/SLICE
TARGET='01ARZ3NDEKTSV4RRFFQ69G5FAV'; AL='org.software-factory.brake-anchor'; CL='org.software-factory.brake-client'
ARCHIVE=__ARCHIVE__; GUARDIAN=__GUARDIAN__; MODULE=__MODULE__; SERVICE=__SERVICE__; CLEANUP=__CLEANUP__; IMAGE=__IMAGE__
def docker(*args,check=True,timeout=15): return subprocess.run(['docker',*args],capture_output=True,text=True,check=check,timeout=timeout)
def anchor_info(target,token):
 r=docker('inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower(): return None
  raise RuntimeError('anchor inspection unresolved')
 o=json.loads(r.stdout)[0]
 if (o['Config']['Labels'] or {}).get(AL)!=token: raise RuntimeError('anchor label mismatch')
 if len(target)==64 and o['Id']!=target: raise RuntimeError('anchor ID mismatch')
 return o
def waitfile(path,sec=15):
 end=time.monotonic()+sec
 while time.monotonic()<end:
  if path.exists(): return
  time.sleep(.02)
 raise RuntimeError('missing '+str(path))
CLIENT=r"""import os,socket,sys
key=open('/key','rb').read().hex() if sys.argv[2]=='valid' else '00'*32
body=('{\"target\":\"'+sys.argv[1]+'\"}').encode()
s=socket.socket(socket.AF_UNIX); s.settimeout(6); s.connect('/brake.sock')
request=('POST /stop HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nx-brake-key: '+key+'\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n\r\n').encode()+body
s.sendall(request); data=b''
while b'\r\n' not in data:
 part=s.recv(256)
 if not part: break
 data+=part
print(data.split(b'\r\n',1)[0].decode())
"""
if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker slice not empty')
inode=CG.stat().st_ino; at=uuid.uuid4().hex; an='sfactory-brake-anchor-'+at; anchor=None
wt=uuid.uuid4().hex; service=None; server=None; client_names=[]
with tempfile.TemporaryDirectory(prefix='sfactory-brake-') as temp:
 root=pathlib.Path(temp); work=root/'source'; work.mkdir(); runtime=root/'runtime'; runtime.mkdir(mode=0o700)
 with tarfile.open(fileobj=io.BytesIO(base64.b64decode(ARCHIVE)),mode='r:gz') as a: a.extractall(work,filter='data')
 env=os.environ.copy(); env['PATH']=str(pathlib.Path.home()/'.cargo/bin')+':'+env.get('PATH',''); env['CARGO_TARGET_DIR']=str(root/'target'); env['CARGO_HOME']=str(root/'cargo'); env['CARGO_BUILD_JOBS']='2'; env['CARGO_PROFILE_DEV_DEBUG']='0'
 dev=root/'dev'; dev.mkdir(); sysroot=root/'sysroot'
 subprocess.run(['apt','download','libssl-dev'],cwd=dev,capture_output=True,check=True,timeout=90)
 packages=list(dev.glob('libssl-dev_*.deb'))
 if len(packages)!=1: raise RuntimeError('development package identity ambiguous')
 subprocess.run(['dpkg-deb','-x',str(packages[0]),str(sysroot)],check=True,timeout=30)
 lib=sysroot/'usr/lib/x86_64-linux-gnu'
 for name in ('libssl.so.3','libcrypto.so.3'): (lib/name).symlink_to('/usr/lib/x86_64-linux-gnu/'+name)
 env['OPENSSL_LIB_DIR']=str(lib); env['OPENSSL_INCLUDE_DIR']=str(sysroot/'usr/include'); env['CFLAGS']='-I'+str(sysroot/'usr/include/x86_64-linux-gnu')
 build=subprocess.run([str(pathlib.Path.home()/'.cargo/bin/cargo'),'build','--locked','-p','watchdog','--features','fixture','--example','docker_brake_fixture'],cwd=work,env=env,capture_output=True,text=True,timeout=600)
 if build.returncode: raise RuntimeError('NUC fixture build failed: '+build.stderr[-3000:])
 for name,code in [('docker_owner_guardian.py',GUARDIAN),('docker_owned_escape_spike.py',MODULE),('service.py',SERVICE),('cleanup.py',CLEANUP)]: (runtime/name).write_text(code)
 key=os.urandom(32)
 while not any(key): key=os.urandom(32)
 (runtime/'brake-key').write_bytes(key); (runtime/'brake-key').chmod(0o444)
 sys.path.insert(0,str(runtime)); from docker_owner_guardian import DisposableContainer
 fallback=DisposableContainer(wt)
 try:
  a=docker('create','--name',an,'--label',AL+'='+at,'--cgroup-parent',PARENT,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','24','--memory','96m','--cpus','0.5','--user','65534:65534','--entrypoint','python3','--pull','never',IMAGE,'-u','-c','import time;time.sleep(40)')
  anchor=a.stdout.strip()
  if len(anchor)!=64 or not anchor_info(anchor,at): raise RuntimeError('anchor identity unresolved')
  docker('start',anchor)
  service_env=os.environ.copy(); service_env['SFACTORY_CGROUP_PARENT']=SLICE
  service=subprocess.Popen([sys.executable,str(runtime/'service.py'),str(runtime),wt],env=service_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  waitfile(runtime/'prepared'); m=json.loads((runtime/'manifest.json').read_text()); fallback.ident=m['id']
  obj=fallback.inspect(m['id'])
  if obj is None or obj['State']['Running'] or obj['HostConfig']['CgroupParent']!=SLICE or obj['Mounts'] or obj['HostConfig']['Binds'] or obj['HostConfig']['NetworkMode']!='none': raise RuntimeError('worker binding mismatch')
  if m['inode']!=inode: raise RuntimeError('slice inode mismatch')
  (runtime/'launch').write_text('go'); waitfile(runtime/'ready')
  deadline=time.monotonic()+8
  while time.monotonic()<deadline:
   l=docker('logs',m['id'],check=False); out=l.stdout+l.stderr
   if 'AFTER_GUARDIAN' in out and 'CGROUP_WRITE_DENIED ' in out: break
   time.sleep(.05)
  else: raise RuntimeError('worker handshake missing')
  sock=runtime/'brake.sock'
  server=subprocess.Popen([str(root/'target/debug/examples/docker_brake_fixture'),str(sock),str(runtime),wt,TARGET],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  lines=queue.Queue()
  def reader():
   for line in server.stdout: lines.put(line.strip())
  threading.Thread(target=reader,daemon=True).start()
  if lines.get(timeout=10)!='READY': raise RuntimeError('brake server unavailable')
  def client(uid,keymode,target):
   tok=uuid.uuid4().hex; name='sfactory-brake-client-'+tok; client_names.append((name,tok))
   r=docker('run','--rm','--name',name,'--label',CL+'='+tok,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','12','--memory','64m','--cpus','0.5','--user',str(uid)+':'+str(uid),
    '--mount','type=bind,source='+str(sock)+',target=/brake.sock,readonly','--mount','type=bind,source='+str(runtime/'brake-key')+',target=/key,readonly',
    '--entrypoint','python3','--pull','never',IMAGE,'-u','-c',CLIENT,target,keymode,timeout=15)
   return r.stdout.strip()
  if not client(1003,'valid',TARGET).startswith('HTTP/1.1 403'): raise RuntimeError('wrong UID not denied')
  if not client(1002,'wrong',TARGET).startswith('HTTP/1.1 403'): raise RuntimeError('wrong key not denied')
  obj=fallback.inspect(m['id'])
  if obj is None or not obj['State']['Running']: raise RuntimeError('unauthorized requests stopped worker')
  if not client(1002,'valid','01ARZ3NDEKTSV4RRFFQ69G5FAW').startswith('HTTP/1.1 409'): raise RuntimeError('unknown target not denied')
  end=time.monotonic()+55
  while True:
   status=client(1002,'valid',TARGET)
   if status.startswith('HTTP/1.1 200'): break
   if not status.startswith('HTTP/1.1 202') or time.monotonic()>=end: raise RuntimeError('authenticated stop unverified: '+status)
   time.sleep(.1)
  if not client(1002,'valid',TARGET).startswith('HTTP/1.1 200'): raise RuntimeError('verified stop retry lost')
  if fallback.inspect(m['id']) is not None: raise RuntimeError('worker remains')
  if CG.stat().st_ino!=inode or 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker empty proof missing')
  print('PASS: real UID 1003 denied; UID 1002 wrong key denied; unknown target denied; UID 1002 stopped owned Docker worker; same slice populated 0',flush=True)
 finally:
  if server is not None:
   if server.poll() is None: server.kill()
   server.wait(timeout=5); server.stdout.close()
  if service is not None:
   if service.poll() is None: service.kill()
   service.wait(timeout=5)
  if fallback.inspect(fallback.ident or fallback.name) is not None: fallback.cleanup()
  for name,tok in client_names:
   r=docker('inspect',name,check=False)
   if r.returncode==0:
    o=json.loads(r.stdout)[0]
    if (o['Config']['Labels'] or {}).get(CL)!=tok: raise RuntimeError('client label mismatch')
    docker('rm','--force',o['Id'])
   elif 'no such object' not in r.stderr.lower(): raise RuntimeError('client state unresolved')
  if anchor_info(anchor or an,at) is not None: docker('rm','--force',anchor or an)
print('LIMIT: real separately provisioned operator, authenticated durable recovery, daemon loss, migration escape and production activation remain unproved')
'''
script=DRIVER.replace('__ARCHIVE__',repr(base64.b64encode(archive.getvalue()).decode())).replace('__GUARDIAN__',repr(guardian)).replace('__MODULE__',repr(module)).replace('__SERVICE__',repr(recovery['SERVICE'])).replace('__CLEANUP__',repr(recovery['CLEANUP'])).replace('__IMAGE__',repr(image))
if __name__=='__main__':
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=300)
 sys.exit(r.returncode)
