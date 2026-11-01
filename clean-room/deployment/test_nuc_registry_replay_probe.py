import unittest
from unittest.mock import Mock,patch
import nuc_registry_replay_probe as p
class Probe(unittest.TestCase):
 def data(self):return {'schema':1,'deployment_id':'dp_123','sdk_uri':'http://127.0.0.1:9084','targets':[{'service':'ClaimLeaseJournal','key':'01ARZ3NDEKTSV4RRFFQ69G5FAM'}]}
 def test_fixed_targets_and_sdk_uri(self):
  data=self.data();self.assertEqual(len(p.targets(data)),1)
  for field,value in [('sdk_uri','http://evil.example:9084'),('deployment_id','dp_../../oops')]:
   bad=dict(data);bad[field]=value
   with self.assertRaises(RuntimeError):p.targets(bad)
  bad=self.data();bad['targets']=[{'service':'ClaimLeaseJournal','key':"x' OR 1=1"}]
  with self.assertRaises(RuntimeError):p.targets(bad)
 def test_state_values_are_hashed_not_returned(self):
  response=Mock(status=200);response.read.return_value=b'{"rows":[{"key":"claim","value_utf8":"secret-token-value"}]}'
  conn=Mock();conn.getresponse.return_value=response
  with patch.object(p.http.client,'HTTPConnection',return_value=conn):out=p.query('ClaimLeaseJournal','01ARZ3NDEKTSV4RRFFQ69G5FAM')
  self.assertEqual(out[0]['key'],'claim');self.assertNotIn('secret-token-value',str(out));self.assertEqual(len(out[0]['value_sha256']),64)
 def test_duplicate_or_unknown_state_key_fails_closed(self):
  response=Mock(status=200);conn=Mock();conn.getresponse.return_value=response
  with patch.object(p.http.client,'HTTPConnection',return_value=conn):
   for raw in (b'{"rows":[{"key":"claim","value_utf8":"x"},{"key":"claim","value_utf8":"y"}]}',b'{"rows":[{"key":"unexpected","value_utf8":"x"}]}'):
    response.read.return_value=raw
    with self.assertRaises(RuntimeError):p.query('ClaimLeaseJournal','01ARZ3NDEKTSV4RRFFQ69G5FAM')
if __name__=='__main__':unittest.main()
