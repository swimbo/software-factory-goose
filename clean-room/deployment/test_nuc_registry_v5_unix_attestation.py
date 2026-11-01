import copy,unittest
import nuc_registry_v5_unix_attestation as att
class UnixAttestation(unittest.TestCase):
 def setUp(self):
  self.intent={'schema':1,'transition_id':att.upgrade.T,'old_manifest_sha256':'a'*64,'new_manifest_sha256':'b'*64};self.unit=att.upgrade.unit()
  self.receipt={'schema':1,'transition_id':att.upgrade.T,'prior_sha256':att.sha(att.install.units()[att.UNIT]),'unit_sha256':att.sha(self.unit),'backup_path':str(att.upgrade.BACKUP),'guarded_binary_sha256':att.install.SOURCE_SHA,'unix_unit_sha256':att.sha(att.upgrade.unix.unit()),'started':False}
 def test_exact_fixed_upgrade_accepted(self):att.validate_upgrade(self.intent,self.receipt,self.unit)
 def test_foreign_transition_and_changed_binary_or_unit_denied(self):
  bad=copy.deepcopy(self.intent);bad['transition_id']='01ARZ3NDEKTSV4RRFFQ69G5FAM'
  with self.assertRaises(RuntimeError):att.validate_upgrade(bad,self.receipt,self.unit)
  for key,value in (('guarded_binary_sha256','c'*64),('unix_unit_sha256','c'*64),('prior_sha256','c'*64),('backup_path','/tmp/foreign'),('started',True)):
   receipt={**self.receipt,key:value}
   with self.subTest(key=key),self.assertRaises(RuntimeError):att.validate_upgrade(self.intent,receipt,self.unit)
  with self.assertRaises(RuntimeError):att.validate_upgrade(self.intent,self.receipt,self.unit+b'changed')
