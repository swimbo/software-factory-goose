import pathlib,unittest
from unittest import mock
import nuc_registry_admission_probe_install as install
class ObserverInstallTests(unittest.TestCase):
 def test_only_exact_pinned_sources_and_unoccupied_targets(self):
  root=pathlib.Path(__file__).parent
  sources={'registry-admin-deny-probe.py':(root/'nuc_registry_admin_deny_probe.py').read_bytes(),'registry-admission-journal-probe.py':(root/'nuc_registry_admission_journal_probe.py').read_bytes()}
  with mock.patch.object(install,'SOURCES',sources),mock.patch.object(install.os,'geteuid',return_value=0),mock.patch.object(install.old,'directory'),mock.patch.object(install.os.path,'lexists',return_value=False):
   self.assertEqual(install.plan()['sources'],install.PINS)
   with mock.patch.object(install,'SOURCES',{**sources,'registry-admin-deny-probe.py':b'changed'}),self.assertRaisesRegex(RuntimeError,'source changed'):install.plan()
if __name__=='__main__':unittest.main()
