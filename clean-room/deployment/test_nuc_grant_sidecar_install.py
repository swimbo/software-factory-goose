import hashlib,importlib.util,pathlib,unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_grant_sidecar_install.py');spec=importlib.util.spec_from_file_location('sidecar',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_fixed_scope_and_separate_names(self):
  self.assertEqual(m.TASK,'01M65GTQYKQQMN3NG1V0EFCVH5');self.assertEqual(m.GEN,'01M65GTQYKNHFXSJSZ55D7T362')
  u=m.units();self.assertEqual(len(u),5)
  for name,body in u.items():
   text=body.decode();self.assertIn('BindsTo=software-factory-goose-private-net.service',text)
   if name.endswith('.service'):
    for token in ('PrivateNetwork=yes','NoNewPrivileges=yes','CapabilityBoundingSet=','MemoryMax=512M','TasksMax=128','CPUQuota=100%'):self.assertIn(token,text)
  launch=u[m.NAME+'launch.socket'].decode();self.assertIn('SocketMode=0600',launch);self.assertIn('SocketGroup=0',launch);self.assertIn('FileDescriptorName=launch-grant',launch)
 def test_fixed_helpers_match_source(self):
  self.assertEqual(hashlib.sha256(m.REGISTER).hexdigest(),m.REGISTER_SHA)
  self.assertEqual(hashlib.sha256(m.SNAPSHOT_SOURCE).hexdigest(),m.SNAPSHOT_SHA)
  self.assertEqual(m.REGISTER,pathlib.Path(__file__).with_name('nuc_grant_sidecar_register.py').read_bytes())
  self.assertEqual(m.SNAPSHOT_SOURCE,pathlib.Path(__file__).with_name('nuc_private_runtime_restart.py').read_bytes())
 def test_plan_conflict_refuses_without_write(self):
  with mock.patch.object(m,'preflight',return_value={'state':1}),mock.patch.object(m,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'state':2})
   store.assert_not_called()
 def test_alias_and_resource_mismatch_refused(self):
  def ctl(*args):
   name=args[1];d={'LoadState':'loaded','ActiveState':'inactive','Names':name,'FragmentPath':str(m.UNIT/name),'DropInPaths':''}
   if name.endswith('.service'):d.update(MainPID='0',MemoryMax=str(512*1024**2),TasksMax='128',CPUQuotaPerSecUSec='1s')
   return '\n'.join(k+'='+v for k,v in d.items())
  with mock.patch.object(m,'ctl',side_effect=ctl):m.verify_new_units()
  def bad(*args):return ctl(*args).replace('Names='+m.NAME+'runtime.service','Names='+m.NAME+'runtime.service alias.service')
  with mock.patch.object(m,'ctl',side_effect=bad):
   with self.assertRaises(RuntimeError):m.verify_new_units()
 def test_nonroot_rejected(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000):
   with self.assertRaisesRegex(RuntimeError,'root required'):m.preflight()
if __name__=='__main__':unittest.main()
