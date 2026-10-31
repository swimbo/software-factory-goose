#!/usr/bin/python3
"""Fixed non-mutating UID2000 HTTP/2 keeper control; disposable fixture only."""
import errno,json,os,pathlib,select,socket,stat,subprocess,sys,time
KEEPER='/usr/local/libexec/software-factory-goose/unix-admin-canary-h2-keeper'
MARKER='/var/lib/software-factory-goose/h2-keeper-canary/handshake/sdk.stopped'
def require(v):
 if not v:raise RuntimeError('native keeper control unavailable')
def line(p,want):
 require(bool(select.select([p.stdout],[],[],8)[0]));require(p.stdout.readline(64)==want+b'\n')
def marker():
 try:fd=os.open(MARKER,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 except FileNotFoundError:return False
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o440) and st.st_size<=32)
  try:os.getxattr(fd,'system.posix_acl_access')
  except OSError as e:require(e.errno==errno.ENODATA)
  else:raise RuntimeError('marker ACL present')
  require(os.read(fd,33)==b'stopped\n');return True
 finally:os.close(fd)
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,)*4)
 f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 require(f.get('NoNewPrivs','').strip()=='1' and all(int(f[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')))
 p=subprocess.Popen([KEEPER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True)
 try:
  line(p,b'initial-ok');require(p.poll() is None);p.stdin.write(b'reuse\n');p.stdin.flush();line(p,b'reuse-ok');require(p.poll() is None)
  fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
  try:
   bad=subprocess.run([KEEPER],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,),timeout=8,check=False)
   require(bad.returncode!=0 and bad.stdout==b'' and len(bad.stderr)<=4096 and b'unexpected inherited descriptor' in bad.stderr)
  finally:os.close(fd)
  print(json.dumps({'schema':1,'stage':'ready','same_h2_connection_reused':True,'extra_fd_denied':True,'mutation':False},sort_keys=True),flush=True)
  end=time.monotonic()+90
  while not marker():
   require(time.monotonic()<end and p.poll() is None);time.sleep(.1)
  p.stdin.write(b'retired\n');p.stdin.flush();line(p,b'retired-denied');require(p.wait(timeout=5)==0)
  try:
   with socket.create_connection(('127.0.0.1',9081),timeout=2):raise RuntimeError('listener still accepting')
  except ConnectionRefusedError:pass
  print(json.dumps({'schema':1,'stage':'closed','held_connection_denied':True,'new_connection_denied':True,'mutation':False},sort_keys=True),flush=True)
 finally:
  if p.poll() is None:p.kill()
  p.wait(timeout=5)
if __name__=='__main__':
 try:main()
 except Exception:print('native keeper control failed or unknown',file=sys.stderr);sys.exit(1)
