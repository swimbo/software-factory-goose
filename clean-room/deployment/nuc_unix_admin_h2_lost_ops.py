#!/usr/bin/python3
"""Send one fixed synthetic registration and deliberately discard its reply."""
import os,socket
P='/var/lib/software-factory-goose/unix-admin-h2-canary/data/sfactory-unix-admin-h2/admin.sock'
def main():
 if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2004,2004,2004,2004):raise RuntimeError('identity')
 status=dict(line.split(':',1) for line in open('/proc/self/status').read().splitlines() if ':' in line)
 if status['NoNewPrivs'].strip()!='1' or not all(status['Cap'+n].strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('capabilities')
 body=b'{"uri":"http://127.0.0.1:9082","force":false,"breaking":false}'
 request=b'POST /deployments HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8)
 try:s.connect(P);s.sendall(request)
 finally:s.close()
 print('DISPATCHED_RESPONSE_UNKNOWN',flush=True)
if __name__=='__main__':main()
