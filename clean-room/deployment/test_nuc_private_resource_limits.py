import hashlib,importlib.util,pathlib,unittest
from unittest import mock
here=pathlib.Path(__file__).parent

def load(name):
 spec=importlib.util.spec_from_file_location(name,here/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=load('nuc_private_resource_limits');b=load('nuc_private_runtime_install')

class Tests(unittest.TestCase):
 def test_all_fixed_units_match_reviewed_bootstrap(self):
  units=b.units()
  self.assertEqual(set(r.UNIT_SHA),{name.removeprefix(r.PREFIX) for name in units})
  for name,digest in r.UNIT_SHA.items():self.assertEqual(hashlib.sha256(units[r.PREFIX+name]).hexdigest(),digest)
 def test_all_services_have_finite_role_specific_bounds(self):
  self.assertEqual(set(r.LIMITS),{name for name in r.UNIT_SHA if name.endswith('.service')})
  for name in r.LIMITS:
   unit=r.dropin(name).decode()
   self.assertIn('MemoryMax=',unit);self.assertIn('TasksMax=',unit);self.assertIn('CPUQuota=',unit)
  self.assertIn('MemoryMax=4G',r.dropin('restate.service').decode())
  self.assertIn('MemoryMax=512M',r.dropin('runtime.service').decode())
 def test_loaded_limits_and_identity_checked(self):
  def props(name):
   data={'LoadState':'loaded','ActiveState':'inactive','FragmentPath':str(r.UNIT/(r.PREFIX+name)),'Names':r.PREFIX+name,'DropInPaths':''}
   if name in r.LIMITS:
    memory,tasks,cpu=r.LIMITS[name];factor={'M':1024**2,'G':1024**3}[memory[-1]]
    data.update(MainPID='0',DropInPaths=str(r.UNIT/(r.PREFIX+name+'.d')/'50-resources.conf'),MemoryMax=str(int(memory[:-1])*factor),TasksMax=str(tasks),CPUQuotaPerSecUSec={'50%':'500ms','100%':'1s','200%':'2s'}[cpu])
   return data
  with mock.patch.object(r,'loaded_properties',side_effect=props):r.verify_loaded()
  def bad(name):
   data=props(name)
   if name=='restate.service':data['MemoryMax']='infinity'
   return data
  with mock.patch.object(r,'loaded_properties',side_effect=bad):
   with self.assertRaisesRegex(RuntimeError,'resource limit mismatch'):r.verify_loaded()
  def alias(name):
   data=props(name)
   if name=='restate.service':data['Names'] += ' unintended.service'
   return data
  with mock.patch.object(r,'loaded_properties',side_effect=alias):
   with self.assertRaisesRegex(RuntimeError,'identity/state mismatch'):r.verify_loaded()
 def test_cpu_time_rejects_unknown_units(self):
  self.assertEqual(r.cpu_usec('500ms'),500000);self.assertEqual(r.cpu_usec('2s'),2000000)
  with self.assertRaises(RuntimeError):r.cpu_usec('infinity')
 def test_plan_change_prevents_mutation(self):
  with mock.patch.object(r,'plan',return_value={'version':1}),mock.patch.object(r,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):r.apply({'version':2})
   store.assert_not_called()
 def test_nonroot_rejected(self):
  with mock.patch.object(r.os,'geteuid',return_value=1000):
   with self.assertRaisesRegex(RuntimeError,'root required'):r.plan()

if __name__=='__main__':unittest.main()
