import unittest
import nuc_sdk5_fd_guard_canary as c
class Fixture(unittest.TestCase):
 def test_distinct_socket_names_and_fixed_privilege(self):
  units=c.units();self.assertEqual(set(units),set(c.SOCKETS)|{c.POS,c.NEG})
  for name in (c.POS,c.NEG):
   s=units[name].decode();self.assertIn('User=sfgoose-control\n',s);self.assertIn('NoNewPrivileges=yes\n',s);self.assertIn('CapabilityBoundingSet=\n',s);self.assertIn('StandardOutput=journal\n',s)
  for unit,name in zip(c.SOCKETS,('intake','worker','launch-grant')):
   s=units[unit].decode();self.assertIn('FileDescriptorName='+name+'\n',s);self.assertIn('RemoveOnStop=yes\n',s);self.assertNotIn('registry-v5-',s)
