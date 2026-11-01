import pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_root_finalization_activation_plan as candidate

class ActivationPlanTests(unittest.TestCase):
    def test_nonroot_refused_before_file_checks(self):
        with mock.patch.object(candidate.os,'geteuid',return_value=1000),mock.patch.object(candidate.guard,'ancestors') as reads:
            with self.assertRaisesRegex(RuntimeError,'root required'):candidate.plan()
            reads.assert_not_called()
if __name__=='__main__':unittest.main()
