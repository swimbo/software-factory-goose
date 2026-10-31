import io,unittest
from unittest.mock import patch
import nuc_ingress_history_output as h
class Output(unittest.TestCase):
 def test_read_only_fixed_result_and_reject_wrong(self):
  class Resp:
   status=200
   def __init__(self,body):self.body=body
   def read(self,n):return self.body[:n]
  class Conn:
   body=b'{"version":"old","count":1}'
   def __init__(self,*a,**k):self.calls=[]
   def request(self,*a,**k):self.calls.append(a)
   def getresponse(self):return Resp(self.body)
   def close(self):pass
  status='NoNewPrivs:\t1\n'+''.join('Cap'+k+':\t0000000000000000\n' for k in ('Eff','Prm','Inh','Bnd','Amb'))
  c=Conn();stdin=type('Input',(),{'buffer':io.BytesIO(b'inv_test\n')})()
  with patch.object(h.sys,'argv',['fixed']),patch.object(h.os,'getuid',return_value=2000),patch.object(h.os,'geteuid',return_value=2000),patch.object(h.os,'getgid',return_value=2000),patch.object(h.os,'getegid',return_value=2000),patch.object(h.pathlib.Path,'read_text',return_value=status),patch.object(h.http.client,'HTTPConnection',return_value=c),patch.object(h.sys,'stdin',stdin),patch.object(h.sys,'stdout',io.StringIO()):
   h.main();self.assertEqual(c.calls[0][0:2],('GET','/restate/output/inv_test'))
   c.body=b'{"version":"new","count":1}';stdin.buffer=io.BytesIO(b'inv_test\n')
   with self.assertRaises(RuntimeError):h.main()
