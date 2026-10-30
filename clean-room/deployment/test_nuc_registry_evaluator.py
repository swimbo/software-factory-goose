import socket,struct,unittest
from unittest.mock import patch
import nuc_registry_evaluator as m
S={'hello.py':'a'*64,'test_hello.py':'b'*64}
class Broker:
 def __init__(self):self.requests=[];self.mutate=None
 def run(self,q):
  self.requests.append(q);args=tuple(q['args']);expected=dict(m.CASES).get(args);tests=q['kind']=='unittest'
  r={'schema':1,'generation':q['generation'],'sequence':q['sequence'],'candidate_sha256':q['candidate_sha256'],'exit_code':0 if tests or expected is not None else 2,'stdout':b'' if tests or expected is None else expected,'stderr':b'Ran 1 test\nOK\n' if tests else (b'error' if expected is None else b''),'exact_cleanup':True}
  if self.mutate:self.mutate(r)
  return r
class Eval(unittest.TestCase):
 def test_all_cases_repeated_and_tests_brokered(self):
  b=Broker();r=m.evaluate(S,b,m.GENERATION);self.assertEqual(r['challenges'],22);self.assertEqual(r['scenario_votes'],[3]*7);self.assertEqual(b.requests[-1]['kind'],'unittest')
 def test_unknown_cleanup_and_mismatched_identity_stop_immediately(self):
  for field,value in [('exact_cleanup',False),('sequence',2),('generation','wrong'),('candidate_sha256',{'hello.py':'c'*64,'test_hello.py':'b'*64}),('stdout',b'x'*(m.MAX_OUTPUT+1))]:
   b=Broker();b.mutate=lambda r:r.update({field:value})
   with self.assertRaises(m.EvaluationUnavailable):m.evaluate(S,b,m.GENERATION)
   self.assertEqual(len(b.requests),1)
 def test_no_broker_or_bad_digest_never_executes(self):
  b=Broker()
  with self.assertRaises(m.EvaluationUnavailable):m.evaluate({'hello.py':'bad','test_hello.py':'b'*64},b,m.GENERATION)
  self.assertFalse(b.requests)
  with self.assertRaises(m.EvaluationUnavailable):m.evaluate(S,None,m.GENERATION)
 def test_transport_wrong_peer_and_timeout_cannot_be_replayed(self):
  class Fake:
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def getsockopt(self,*args):return struct.pack('3i',123,2001,2001)
  with patch.object(socket,'SO_PEERCRED',17,create=True):
   broker=m.UnixBroker(Fake,lambda:True)
   with self.assertRaises(m.EvaluationUnavailable):broker.run({'sequence':1})
   with self.assertRaises(m.EvaluationUnavailable):broker.run({'sequence':1})
   with self.assertRaises(m.EvaluationUnavailable):broker.run({'sequence':2})
if __name__=='__main__':unittest.main()
