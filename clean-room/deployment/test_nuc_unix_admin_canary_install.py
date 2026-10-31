import ast,unittest
import nuc_unix_admin_canary_install as m
class CanaryInstall(unittest.TestCase):
 def test_config_and_service_are_fixture_only(self):
  self.assertEqual(m.CONF,b'listen-mode = "tcp"\n[admin]\nlisten-mode = "unix"\n')
  units=m.units();self.assertEqual(set(units),{m.NET,m.SERVER});s=units[m.SERVER].decode()
  self.assertIn('User=sfgoose-journal',s);self.assertIn('JoinsNamespaceOf='+m.NET,s);self.assertIn('--base-dir '+str(m.DATA),s);self.assertIn('CapabilityBoundingSet=\n',s);self.assertIn('NoNewPrivileges=yes',s)
  self.assertIn('ProtectSystem=strict\nReadWritePaths='+str(m.DATA),s);self.assertIn('ProtectHome=yes\nPrivateTmp=yes\nUMask=0077',s);self.assertIn('Environment=TOKIO_WORKER_THREADS=2',s)
  self.assertNotIn('/var/lib/software-factory-goose/journal',s)
 def test_fixed_probes_compile(self):
  ast.parse(m.PROBE_SOURCE);ast.parse(m.ANCHOR_SOURCE)
  self.assertNotIn(b'except (ConnectionRefusedError,TimeoutError)',m.PROBE_SOURCE)
if __name__=='__main__':unittest.main()
