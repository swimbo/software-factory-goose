import json,unittest
from unittest import mock
import nuc_grant_expiry_canary as c
class ExpiryCanary(unittest.TestCase):
 def test_early_probe_is_denied_before_any_request(self):
  grant={'scope':{},'token_sha256':'a','expires_at_ms':9999999999999}; claim={'token_sha256':'a','expires_at_ms':grant['expires_at_ms']}; done={'scope':{}}
  def read(path,mode):
   return json.dumps(claim if path.name=='grant-journal-pull-complete.json' else grant if path.name=='grant-journal-grant.json' else done).encode()
  with mock.patch.object(c.os,'geteuid',return_value=0),mock.patch.object(c.os.path,'lexists',return_value=False),mock.patch.object(c.install,'read',side_effect=read),mock.patch.object(c.subprocess,'run') as command:
   with self.assertRaises(RuntimeError):c.plan()
   command.assert_not_called()
if __name__=='__main__':unittest.main()
