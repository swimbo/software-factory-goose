#!/usr/bin/python3
"""One non-retrying fixed registration, invoked only inside the private namespace."""
import http.client
import json
import os
import socket
import time

if os.geteuid() != 2000:
 raise RuntimeError('registration identity mismatch')
for port in (9081,9070):
 for _ in range(150):
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.1): break
  except OSError: time.sleep(.1)
 else: raise RuntimeError('private service unavailable')
body=json.dumps({'uri':'http://127.0.0.1:9081'},separators=(',',':')).encode()
conn=http.client.HTTPConnection('127.0.0.1',9070,timeout=10)
try:
 conn.request('POST','/deployments',body,{'Content-Type':'application/json'})
 response=conn.getresponse()
 if response.status not in (200,201): raise RuntimeError('registration rejected or unknown')
 if len(response.read(65537)) > 65536: raise RuntimeError('registration response too large; unknown')
finally:conn.close()
