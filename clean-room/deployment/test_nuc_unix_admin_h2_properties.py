"""Guard the exact manager-property schema used by the H2 fixture."""
import importlib.util,pathlib,sys,unittest
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import nuc_unix_admin_h2_activate as activation
class PropertiesTest(unittest.TestCase):
 def test_required_properties_are_requested_and_returned(self):
  names=('Names','LoadState','ActiveState','MainPID','Job','FragmentPath','DropInPaths','Type','User','Group','PrivateNetwork','JoinsNamespaceOf','BindsTo','NoNewPrivileges','CapabilityBoundingSet','AmbientCapabilities','ProtectSystem','ReadWritePaths','ProtectHome','PrivateTmp','Environment','ControlGroup')
  def ctl(*args):
   requested=next(x for x in args if x.startswith('--property='))
   self.assertTrue(set(names)<=set(requested.removeprefix('--property=').split(',')))
   return '\n'.join(name+'=value' for name in names)
  with patch.object(activation.old,'ctl',ctl):
   self.assertEqual(set(activation.properties('fixed.service')),set(names))
if __name__=='__main__':unittest.main()
