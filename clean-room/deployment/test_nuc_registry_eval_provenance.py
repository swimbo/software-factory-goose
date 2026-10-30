import copy,hashlib,unittest
from nuc_registry_eval_provenance import InvalidProvenance,validate
G='01M65RMR3F04YB1B016EBBSXGQ'
class Provenance(unittest.TestCase):
 def setUp(self):
  self.files={'hello.py':b'hello','test_hello.py':b'tests'};self.writer=b'writer';self.relay=b'relay';h={k:hashlib.sha256(v).hexdigest() for k,v in self.files.items()};b='a'*64
  self.receipt={'schema':1,'generation':G,'binding_sha256':b,'writer_id':'b'*64,'goose_id':'c'*64,'candidate_sha256':h,'kernel_closed_frozen_empty':True,'exact_ids_removed':True,'slice_retained_frozen':True,'engine_reconciled_for_exact_ids':True}
  self.manifest={'schema':1,'generation':G,'binding_sha256':b,'candidate_sha256':h,'writer_result_sha256':hashlib.sha256(self.writer).hexdigest(),'relay_done_sha256':hashlib.sha256(self.relay).hexdigest()}
 def test_valid_and_mutations(self):
  validate(G,self.receipt,self.manifest,self.writer,self.relay,self.files)
  for field in ('kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids'):
   receipt=copy.deepcopy(self.receipt);receipt[field]=False
   with self.subTest(field=field),self.assertRaises(InvalidProvenance):validate(G,receipt,self.manifest,self.writer,self.relay,self.files)
  for writer,relay,files in ((b'other',self.relay,self.files),(self.writer,b'other',self.files),(self.writer,self.relay,{**self.files,'hello.py':b'altered'})):
   with self.assertRaises(InvalidProvenance):validate(G,self.receipt,self.manifest,writer,relay,files)
 def test_binding_and_generation_cannot_change(self):
  manifest=copy.deepcopy(self.manifest);manifest['binding_sha256']='b'*64
  with self.assertRaises(InvalidProvenance):validate(G,self.receipt,manifest,self.writer,self.relay,self.files)
  with self.assertRaises(InvalidProvenance):validate('01M65RMR3F04YB1B016EBBSXGP',self.receipt,self.manifest,self.writer,self.relay,self.files)

class GenerationSocket(unittest.TestCase):
 def test_untrusted_generation_rejected_before_listener(self):
  import nuc_registry_eval_server_per_generation as server
  for generation in ('../other', '01m65rmr3f04y1b016ebbsxgq', '', None):
   with self.subTest(generation=generation),self.assertRaises(server.Unavailable):server.validate_listener(-1,lambda *_:None,generation)

class RegistryAdmission(unittest.TestCase):
 def test_transport_denies_changed_generation_before_backend(self):
  import struct
  from unittest import mock
  import nuc_registry_eval_runtime_per_generation as runtime
  class Connection:
   sent=None
   def getsockopt(self,*args):return struct.pack('3i',123,2002,2002)
   def settimeout(self,value):pass
   def recv(self,size):return b'{"challenge":"test"}\n'
   def sendall(self,data):self.sent=data
  conn=Connection();inner=mock.Mock()
  with mock.patch.object(runtime.server.socket,'SO_PEERCRED',17,create=True),mock.patch.object(runtime.provision,'selected',return_value=('01M65RMR3F04YB1B016EBBSXGP','x',{})),mock.patch.object(runtime.gate,'admission',__import__('contextlib').nullcontext):
   runtime.handle_connection(conn,inner,G)
  self.assertEqual(conn.sent,b'{"error":"unavailable"}\n');inner.run.assert_not_called()
 def test_changed_generation_denied_and_valid_call_holds_gate(self):
  import contextlib
  from unittest import mock
  import nuc_registry_eval_runtime_per_generation as runtime
  held=[]
  @contextlib.contextmanager
  def gate():
   held.append(True)
   try:yield
   finally:held.pop()
  class Inner:
   calls=0
   def run(self,uid,request):
    self.calls+=1
    if not held:raise AssertionError('admission lock not held')
    return 'ok'
  inner=Inner();guarded=runtime.GuardedBroker(inner,G)
  with mock.patch.object(runtime.gate,'admission',gate),mock.patch.object(runtime.provision,'selected',return_value=('01M65RMR3F04YB1B016EBBSXGP','x',{})):
   with self.assertRaises(runtime.broker.Unavailable):guarded.run(2002,{})
  self.assertEqual(inner.calls,0)
  with mock.patch.object(runtime.gate,'admission',gate),mock.patch.object(runtime.provision,'selected',return_value=(G,'x',{})):
   self.assertEqual(guarded.run(2002,{}),'ok')
  self.assertEqual(inner.calls,1);self.assertEqual(held,[])
