import unittest
import nuc_ingress_fence_probe as p
class Response:
 def __init__(self,status,data):self.status=status;self.data=data
 def read(self,limit):return self.data[:limit]
 def getheader(self,key):return "inv_synthetic" if key=="x-restate-id" else None
class Connection:
 def __init__(self,status,data):self.reply=Response(status,data);self.calls=[]
 def request(self,method,path,headers):self.calls.append((method,path,headers))
 def getresponse(self):return self.reply
class ProbeTests(unittest.TestCase):
 def test_failed_or_oversize_response_is_not_accepted(self):
  for status,data in ((503,b'unknown'),(200,b'x'*(p.MAX+1))):
   c=Connection(status,data)
   with self.assertRaises(RuntimeError):p.post(c,'/restate/call/FenceFixture/history/increment')
   self.assertEqual(len(c.calls),1)
 def test_success_returns_only_complete_body(self):
  c=Connection(200,b'{"version":"old","count":1}')
  self.assertEqual(p.post(c,'/restate/call/FenceFixture/history/increment'),c.reply.data)
  self.assertEqual(len(c.calls),1)

 def test_send_requires_matching_acknowledgement_without_retry(self):
  good=Connection(202,b'{"invocationId":"inv_synthetic","status":"Accepted"}')
  self.assertEqual(p.send(good,'/restate/send/FenceFixture/blocked/hold'),'inv_synthetic')
  bad=Connection(202,b'{"invocationId":"inv_other","status":"Accepted"}')
  with self.assertRaises(RuntimeError):p.send(bad,'/restate/send/FenceFixture/blocked/hold')
  self.assertEqual(len(bad.calls),1)

class ConnectionReuse(unittest.TestCase):
 def test_requires_both_original_connections(self):
  from unittest.mock import patch
  import nuc_ingress_fence_probe as p
  class C: pass
  direct=C(); ingress=C(); direct.sock=object(); ingress.sock=object()
  held=direct.sock; original=ingress.sock
  with patch.object(p,'response',return_value=(200,b'{"services":[{"name":"FenceFixture"}]}')), patch.object(p,'post',return_value=b'{"version":"old","count":1}'):
   p.verify_reuse(direct,held,ingress,original)
   direct.sock=object()
   with self.assertRaises(RuntimeError):p.verify_reuse(direct,held,ingress,original)
   direct.sock=held; ingress.sock=object()
   with self.assertRaises(RuntimeError):p.verify_reuse(direct,held,ingress,original)
