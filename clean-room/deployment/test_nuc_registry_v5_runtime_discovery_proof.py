import copy,unittest
import nuc_registry_v5_runtime_activate as runtime
class DiscoveryProofTests(unittest.TestCase):
 def setUp(self):
  self.canary={'schema':1,'probe_sha256':runtime.discovery.SOURCE_SHA,'server_sha256':runtime.discovery_canary.SERVER_SHA,'positive_discovery':True,'inherited_connected_fd_denied':True,'units_stopped':True,'registration':False,'production_changed':False}
  self.shape={'schema':1,'production_access':False,'inherited':{'character':True,'fifo':False,'readonly':False,'same_device_inode':False,'same_rdev':True},'devnull':{'character':True,'fifo':False,'readonly':False,'same_device_inode':True,'same_rdev':True}}
 def test_exact_receipts_are_accepted(self):runtime.validate_discovery_proofs(self.canary,self.shape)
 def test_missing_negative_or_changed_probe_denied(self):
  for field,value in (('inherited_connected_fd_denied',False),('probe_sha256','0'*64),('units_stopped',1)):
   c=copy.deepcopy(self.canary);c[field]=value
   with self.subTest(field=field),self.assertRaises(RuntimeError):runtime.validate_discovery_proofs(c,self.shape)
 def test_wrong_stdio_or_extra_fields_denied(self):
  for edit in ('inode','extra'):
   shape=copy.deepcopy(self.shape)
   if edit=='inode':shape['devnull']['same_device_inode']=False
   else:shape['extra']=True
   with self.subTest(edit=edit),self.assertRaises(RuntimeError):runtime.validate_discovery_proofs(self.canary,shape)
if __name__=='__main__':unittest.main()
