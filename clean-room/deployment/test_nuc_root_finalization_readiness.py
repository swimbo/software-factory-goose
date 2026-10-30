import pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_root_finalization_readiness as readiness

class ReadinessTests(unittest.TestCase):
    def test_failed_native_check_does_not_create_success(self):
        plan={'schema':1}
        with mock.patch.object(readiness,'plan',return_value=plan),mock.patch.object(readiness.auth,'create') as create,mock.patch.object(readiness.auth,'run_unit',return_value=mock.Mock(returncode=1,stdout=b'',stderr=b'')):
            with self.assertRaisesRegex(RuntimeError,'readiness unresolved'):readiness.apply(plan)
            create.assert_called_once();self.assertEqual(create.call_args.args[0],readiness.INTENT)
    def test_exact_native_result_records_no_authorization(self):
        plan={'schema':1};line=b'PASS: fixed unknown evidence verified; request_sha256='+b'a'*64+b'\n'
        with mock.patch.object(readiness,'plan',return_value=plan),mock.patch.object(readiness.auth,'create') as create,mock.patch.object(readiness.auth,'run_unit',return_value=mock.Mock(returncode=0,stdout=line,stderr=b'')):
            result=readiness.apply(plan)
            self.assertEqual(result['record_sha256'],'a'*64);self.assertFalse(result['authorization_published']);self.assertEqual(create.call_count,2)
if __name__=='__main__':unittest.main()
