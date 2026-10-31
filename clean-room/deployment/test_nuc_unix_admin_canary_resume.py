import json,unittest
import nuc_unix_admin_canary_resume as m
class Resume(unittest.TestCase):
 def test_fixture_identity_is_json_roundtrip_stable(self):
  spec={'fixture_inodes':{k:list(v) for k,v in m.EXPECTED.items()}}
  self.assertEqual(json.loads(json.dumps(spec)),spec)
if __name__=='__main__':unittest.main()
