#!/usr/bin/python3
"""Dispatch once to the distinct recovery URI and discard the drained reply.

The supervisor durably fences the attempt before execution. HTTP status, body
and deployment ID never reach its caller; only a separate fixed GET can resolve
registration. The prior 9082 attempt must never use this helper.
"""
import http.client,os,pathlib,socket,sys
SOCKET='/var/lib/software-factory-goose/unix-admin-h2-canary/data/sfactory-unix-admin-h2/admin.sock'
BODY=b'{"uri":"http://127.0.0.1:9086","force":false,"breaking":false}'
class Connection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(SOCKET)
def main():
 if len(sys.argv)!=1 or (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2004,)*4:raise RuntimeError('identity unavailable')
 status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 if status.get('NoNewPrivs','').strip()!='1' or any(status.get('Cap'+n,'').strip()!='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('privilege unavailable')
 c=Connection('localhost',timeout=8)
 try:
  c.request('POST','/deployments',BODY,{'Content-Type':'application/json','Accept':'application/json','Connection':'close'})
  response=c.getresponse();response.read(65537)
 except (OSError,http.client.HTTPException):
  pass  # A transport failure is equally unknown, with no automatic retry.
 finally:c.close()
 print('DISPATCHED_RESPONSE_UNKNOWN',flush=True)
if __name__=='__main__':main()
