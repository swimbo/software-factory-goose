import unittest
import nuc_unix_admin_canary_sdk_v4_install as m
class V4(unittest.TestCase):
 def test_new_paths_preserve_v3_and_fence(self):
  u=m.units();self.assertEqual(set(u),{m.OLD,m.NEW})
  for name,role in ((m.OLD,'old'),(m.NEW,'new')):
   s=u[name].decode();self.assertIn(str(m.BIN)+' '+role,s);self.assertIn('sdk-v4-'+role+'.log',s);self.assertNotIn('ExecStart='+str(m.prior.BIN)+' ',s);self.assertEqual('ConditionPathExists=!'+str(m.prior.HANDSHAKE/'old.retired') in s,role=='old')
if __name__=='__main__':unittest.main()
