import socket,struct,unittest
from unittest.mock import patch
import nuc_registry_eval_server as m
class Conn:
 def __init__(self,uid,raw):self.uid=uid;self.raw=raw;self.output=b'';self.reads=0
 def getsockopt(self,*a):return struct.pack('3i',100,self.uid,self.uid)
 def settimeout(self,x):pass
 def recv(self,n):self.reads+=1;r=self.raw[:n];self.raw=self.raw[n:];return r
 def sendall(self,v):self.output+=v
class Broker:
 def __init__(self):self.calls=0
 def run(self,uid,q):self.calls+=1;return {'stdout':b'ok','stderr':b''}
class ServerTests(unittest.TestCase):
 def test_wrong_uid_denied_before_body_read(self):
  c=Conn(2001,b'{}\n');b=Broker()
  with patch.object(socket,'SO_PEERCRED',17,create=True):m.handle(c,b)
  self.assertEqual(c.reads,0);self.assertEqual(b.calls,0)
 def test_duplicate_keys_denied_before_broker(self):
  c=Conn(2002,b'{"x":1,"x":2}\n');b=Broker()
  with patch.object(socket,'SO_PEERCRED',17,create=True):m.handle(c,b)
  self.assertEqual(b.calls,0);self.assertEqual(c.output,b'{"error":"unavailable"}\n')
if __name__=='__main__':unittest.main()
