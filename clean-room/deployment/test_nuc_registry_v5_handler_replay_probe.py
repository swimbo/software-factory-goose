import unittest
from unittest.mock import patch
import nuc_registry_v5_handler_replay_probe as p
class HandlerProbe(unittest.TestCase):
 def test_rejects_wrong_deployment_and_never_returns_raw_metadata(self):
  class Reply:
   status=200
   def read(self,n):return b'{"safe":true}'
   def getheader(self,name):return 'inv_test'
  class Conn:
   def __init__(self,*a,**kw):self.calls=[]
   def request(self,*a,**kw):self.calls.append(a)
   def getresponse(self):return Reply()
   def close(self):pass
  c=Conn()
  with patch.object(p.http.client,'HTTPConnection',return_value=c),patch.object(p,'query',return_value=[{'pinned_deployment_id':'dp_new'}]):
   self.assertEqual(p.call('ClaimLeaseJournal','01ARZ3NDEKTSV4RRFFQ69G5FAM','status',b'','dp_new'),{'safe':True});self.assertEqual(c.calls[0][0],'POST')
  with patch.object(p.http.client,'HTTPConnection',return_value=c),patch.object(p,'query',return_value=[{'pinned_deployment_id':'dp_old'}]),self.assertRaises(RuntimeError):p.call('ClaimLeaseJournal','01ARZ3NDEKTSV4RRFFQ69G5FAM','status',b'','dp_new')
 def test_duplicate_response_fields_rejected(self):
  with self.assertRaises(RuntimeError):p.parse(b'{"a":1,"a":2}')
