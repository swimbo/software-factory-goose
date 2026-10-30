import importlib.util,pathlib,unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_private_runtime_restart.py');spec=importlib.util.spec_from_file_location('restart',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def fixture(self):return {'boot_id':'b','files':{},'sockets':{},'support':{},'pg_system_id':'7702303394074795435','runtime':{'pid':1}}
 def test_changed_plan_never_writes(self):
  with mock.patch.object(m,'plan',return_value={'a':1}),mock.patch.object(m,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'a':2})
   store.assert_not_called()
 def test_exact_restart_and_receipt(self):
  before=self.fixture();after={**before,'runtime':{'pid':2}};approved={'before':before};writes=[];calls=[]
  with mock.patch.object(m,'plan',return_value=approved),mock.patch.object(m,'store',side_effect=lambda p,v:writes.append(p)),mock.patch.object(m,'command',side_effect=lambda args,timeout=15:calls.append(args)),mock.patch.object(m,'snapshot',return_value=after),mock.patch('builtins.print'):
   m.apply(approved)
  self.assertEqual(calls,[['/usr/bin/systemctl','restart',m.PREFIX+m.TARGET]])
  self.assertEqual(writes,[m.INTENT,m.DONE])
 def test_unchanged_pid_or_changed_support_withholds_done(self):
  before=self.fixture();approved={'before':before}
  for after in (before,{**before,'support':{'changed':1},'runtime':{'pid':2}}):
   writes=[]
   with mock.patch.object(m,'plan',return_value=approved),mock.patch.object(m,'store',side_effect=lambda p,v:writes.append(p)),mock.patch.object(m,'command'),mock.patch.object(m,'snapshot',return_value=after):
    with self.assertRaises(RuntimeError):m.apply(approved)
   self.assertEqual(writes,[m.INTENT])
 def test_restart_timeout_retains_started_without_done(self):
  approved={'before':self.fixture()};writes=[]
  with mock.patch.object(m,'plan',return_value=approved),mock.patch.object(m,'store',side_effect=lambda p,v:writes.append(p)),mock.patch.object(m,'command',side_effect=TimeoutError):
   with self.assertRaises(TimeoutError):m.apply(approved)
  self.assertEqual(writes,[m.INTENT])
if __name__=='__main__':unittest.main()
