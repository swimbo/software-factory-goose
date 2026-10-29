#!/usr/bin/env python3
"""Disposable UID-gated synthetic Goose service transport; no production activation."""
import json,socket,struct,threading
from trusted_tool_relay import Refused
from nuc_bifrost_stream import no_duplicates
from nuc_stream_contract import REQUEST_FRAME_BYTES,RELAY_REPLY_BYTES,reply_fits
LIMIT=REQUEST_FRAME_BYTES

def send_reply(connection,result):
 response=json.dumps({'ok':True,'value':result},separators=(',',':')).encode()
 if not reply_fits(len(response)):raise Refused('response too large')
 connection.sendall(response)

class Listener:
 def __init__(self,path,service):
  self.service=service;self.socket=socket.socket(socket.AF_UNIX);self.socket.bind(str(path));self.socket.listen(4);self.socket.settimeout(.2);self.stop_event=threading.Event()
 def close(self):self.stop_event.set();self.socket.close()
 def serve(self):
  while not self.stop_event.is_set():
   try:c,_=self.socket.accept()
   except socket.timeout:continue
   except OSError:break
   with c:
    c.settimeout(30)
    try:
     _,uid,_=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
     if uid!=1001:continue
     data=b''
     while b'\n' not in data and len(data)<=LIMIT:
      chunk=c.recv(4096)
      if not chunk:break
      data+=chunk
     if len(data)>LIMIT or not data.endswith(b'\n'):raise Refused('invalid frame')
     request=json.loads(data,object_pairs_hook=no_duplicates);result=self.service.request(request)
     send_reply(c,result)
    except Exception:
     try:c.sendall(b'{"ok":false,"value":null}')
     except OSError:pass
