import pathlib,tempfile,unittest
import nuc_sdk5_discovery_native_canary as canary
class DiscoveryCanaryTests(unittest.TestCase):
 def test_exact_unit_and_prefix_dropins_are_refused(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d);canary.collision(canary.POS,[d]);(path/'service.d').mkdir()
   with self.assertRaisesRegex(RuntimeError,'unit collision'):canary.collision(canary.POS,[d])
if __name__=='__main__':unittest.main()
