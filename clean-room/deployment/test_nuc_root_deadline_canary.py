import unittest
import nuc_root_deadline_canary as d
class Fake:
 def __init__(self,values):self.values=values;self.calls=[]
 def property_value(self,unit,key):return self.values[key]
 def run(self,*args):self.calls.append(args);self.values['ActiveState']='inactive'
class CanaryCleanupTests(unittest.TestCase):
 def test_collected_unit_only_accepted_when_inactive_and_idle(self):
  v={'LoadState':'not-found','ActiveState':'inactive','Job':'','Names':'','Transient':'no','FragmentPath':'','DropInPaths':''};f=Fake(v)
  self.assertEqual(d.cleanup_transient(f,'owned.timer'),'already_collected');self.assertEqual(f.calls,[])
  v['Job']='12'
  with self.assertRaises(RuntimeError):d.cleanup_transient(f,'owned.timer')
 def test_loaded_unit_requires_exact_transient_identity_before_stop(self):
  v={'LoadState':'loaded','ActiveState':'active','Job':'','Names':'foreign.timer','Transient':'yes','FragmentPath':'/run/systemd/transient/owned.timer','DropInPaths':''};f=Fake(v)
  with self.assertRaises(RuntimeError):d.cleanup_transient(f,'owned.timer')
  self.assertEqual(f.calls,[])
  v['Names']='owned.timer'
  self.assertEqual(d.cleanup_transient(f,'owned.timer'),'stopped');self.assertEqual(len(f.calls),1)
if __name__=='__main__':unittest.main()
