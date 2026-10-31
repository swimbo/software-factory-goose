import unittest
import nuc_unix_admin_h2_sdk_install as x
class Units(unittest.TestCase):
 def test_fixed_isolation_and_retirement(self):
  units=x.units();self.assertEqual(set(units),{x.OLD,x.NEW})
  for name,content in units.items():
   text=content.decode();self.assertIn('JoinsNamespaceOf='+x.NET,text);self.assertIn('User=sfgoose-control',text);self.assertIn('CapabilityBoundingSet=\n',text);self.assertIn('NoNewPrivileges=yes',text);self.assertIn('ExecStart='+str(x.pinned.BIN),text)
   self.assertEqual('ConditionPathExists=!' in text,name==x.OLD)
