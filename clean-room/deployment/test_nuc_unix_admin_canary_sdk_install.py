import ast,pathlib,unittest
import nuc_unix_admin_canary_sdk_install as m
class SDKInstall(unittest.TestCase):
 def test_units_fixed_isolated_roles_and_no_openfile(self):
  units=m.units();self.assertEqual(set(units),{m.OLD,m.NEW})
  for name,role in ((m.OLD,'old'),(m.NEW,'new')):
   s=units[name].decode();self.assertIn('User=sfgoose-control\nGroup=sfgoose-control',s);self.assertIn('JoinsNamespaceOf='+m.base.NET,s);self.assertIn('StandardInput=null\nStandardOutput=append:'+str(m.HANDSHAKE/('sdk-'+role+'.log')),s);self.assertIn('LimitFSIZE=1M',s);self.assertIn('ExecStart='+str(m.BIN)+' '+role,s);self.assertNotIn('OpenFile=',s);self.assertNotIn('Sockets=',s)
   self.assertIn('Environment=TOKIO_WORKER_THREADS=2',s)
   self.assertEqual('ConditionPathExists=!'+str(m.HANDSHAKE/'old.retired') in s,role=='old')
 def test_helper_compiles(self):
  ast.parse(pathlib.Path(__file__).with_name('nuc_unix_admin_canary_fixed_ops.py').read_text())
if __name__=='__main__':unittest.main()
