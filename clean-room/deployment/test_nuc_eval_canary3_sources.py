import hashlib
import pathlib
import unittest

import nuc_eval_canary3_provision as provision


class OwnerLossScope(unittest.TestCase):
    def test_fresh_and_bound_sources(self):
        root = pathlib.Path(__file__).parent / 'evaluator_canary3'
        targets = [provision.target(i) for i in range(1, 23)]
        self.assertEqual(len(set(targets)), 22)
        self.assertNotIn(provision.G, targets)
        self.assertNotEqual(provision.G, '01M65RMR3F04YB1B016EBBSXGN')
        for name, digest in provision.PINS.items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)

    def test_candidate_blocks_with_new_session_child(self):
        text = provision.REFERENCE.decode()
        compile(text, 'hello.py', 'exec')
        self.assertIn('os.fork()', text)
        self.assertIn('os.setsid()', text)
        self.assertIn('while True: time.sleep(1)', text)

    def test_service_has_no_automatic_restart(self):
        import nuc_eval_canary3_service_install as service
        self.assertIn(b'Restart=no\n', service.SERVICE)
        self.assertIn(b'CapabilityBoundingSet=\n', service.SERVICE)
        self.assertIn(b'/evaluator3/broker.sock', service.SOCKET)


class DurableReplay(unittest.TestCase):
 def test_existing_unknown_intent_never_calls_backend(self):
  import importlib.util, json, os, tempfile
  from unittest import mock
  root=pathlib.Path(__file__).parent/'evaluator_canary3'
  import sys
  sys.path.insert(0,str(root))
  spec=importlib.util.spec_from_file_location('eval3_broker_test',root/'nuc_registry_eval_broker.py')
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  class Backend:
   calls=0
   def launch_and_reconcile(self,*args):
    self.calls+=1
    raise RuntimeError('unexpected dispatch')
  candidate={name:'a'*64 for name in ('hello.py','test_hello.py')}
  request={'schema':1,'generation':provision.G,'sequence':1,'kind':'hello','args':[],'candidate_sha256':candidate}
  with tempfile.TemporaryDirectory() as directory:
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
   try:
    (pathlib.Path(directory)/'01.intent').write_text(json.dumps(request))
    real_stat=os.fstat(fd)
    class RootStat:
     st_mode=real_stat.st_mode
     st_uid=0
     st_gid=0
    backend=Backend()
    with mock.patch.object(module.os,'fstat',return_value=RootStat()):
     broker=module.Broker(fd,candidate,backend,provision.G,lambda *_:None)
    with self.assertRaises(module.Unavailable):broker.run(2002,request)
    self.assertEqual(backend.calls,0)
    self.assertFalse((pathlib.Path(directory)/'01.done').exists())
   finally:os.close(fd)

if __name__ == '__main__':
    unittest.main()
