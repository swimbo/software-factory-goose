#!/usr/bin/python3
"""Fixed UID2004 private-namespace probe for four retired SDK endpoints."""
import errno,json,os,pathlib,socket,sys
PORTS=(9081,9082,9083,9084)
def require(v,m):
 if not v:raise RuntimeError(m)
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,)*4,'identity unavailable')
 status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 require(status.get('NoNewPrivs','').strip()=='1' and all(status.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privilege unavailable')
 for port in PORTS:
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
   s.settimeout(2);require(s.connect_ex(('127.0.0.1',port))==errno.ECONNREFUSED,'old listener unavailable')
 for path in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
  for line in pathlib.Path(path).read_text().splitlines()[1:]:
   fields=line.split();require(len(fields)>=4,'socket table unavailable')
   port=int(fields[1].rsplit(':',1)[1],16)
   require(not (port in PORTS and fields[3] in ('01','0A')),'retired socket remains')
 ns=os.stat('/proc/self/ns/net')
 print(json.dumps({'schema':1,'ports':list(PORTS),'listeners_and_established_absent':True,'namespace_dev':ns.st_dev,'namespace_ino':ns.st_ino},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:
  print('retirement listener observation unavailable',file=sys.stderr);sys.exit(1)
