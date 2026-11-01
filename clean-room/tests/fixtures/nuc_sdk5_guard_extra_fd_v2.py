#!/usr/bin/python3
"""Fixed synthetic canary: pass one connected fixture FD through exec."""
import os,socket,sys
TARGET='/run/software-factory-goose/sdk5-guard-canary-extra-v2.sock'
BINARY='/usr/local/libexec/software-factory-goose/sdk5-startup-guard-canary'
if len(sys.argv)!=1 or os.geteuid()!=2000:raise RuntimeError('fixed canary scope unavailable')
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3);s.connect(TARGET);os.set_inheritable(s.fileno(),True)
os.execve(BINARY,[BINARY],dict(os.environ))
