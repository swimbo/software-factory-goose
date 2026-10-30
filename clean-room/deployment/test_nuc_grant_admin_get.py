import unittest
from nuc_grant_admin_get import summary
class AdminGetTests(unittest.TestCase):
 def test_summary_reports_only_selected_metadata(self):
  out=summary(b'{"id":"d1","uri":"http://127.0.0.1:9082","services":[{"name":"ClaimLeaseJournal","other":"private"}]}','d1')
  self.assertTrue(out['id_matches']); self.assertEqual(out['service_entries'][0]['name'],'ClaimLeaseJournal'); self.assertNotIn('private',str(out))
 def test_nonobject_refused(self):
  with self.assertRaises(ValueError): summary(b'[]','d1')
if __name__=='__main__':unittest.main()
