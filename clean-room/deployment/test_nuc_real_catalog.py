import hashlib,unittest
from nuc_real_catalog import build
class RealCatalog(unittest.TestCase):
 def test_scope_binds_all_inputs(self):
  c,e=build({'principal':'fixture-submitter'},'a'*40)
  self.assertEqual(c['launch_scope']['task_id'],c['task_id']);self.assertEqual(c['launch_scope']['spec']['base_revision'],c['request']['base_revision']);self.assertEqual(c['evidence_sha256'],hashlib.sha256(e).hexdigest())
  other,_=build({'principal':'fixture-submitter'},'b'*40);self.assertNotEqual(c['launch_scope']['catalog_sha256'],other['launch_scope']['catalog_sha256'])
 def test_bad_baseline_fails(self):
  with self.assertRaises(ValueError):build({'principal':'p'},'bad')
if __name__=='__main__':unittest.main()
