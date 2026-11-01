import json,pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_sdk5_unix_admin_fixed as admin

class FixedAdminTests(unittest.TestCase):
    def test_one_post_disables_force_and_records_exact_ack(self):
        response=mock.Mock(status=201);response.read.return_value=json.dumps({'id':'dp_Test1','services':[{'name':x} for x in admin.SERVICES]}).encode()
        conn=mock.Mock();conn.getresponse.return_value=response
        metadata={'id':'dp_Test1','uri':admin.URI,'services':[{'name':x} for x in admin.SERVICES]}
        with mock.patch.object(admin,'Connection',return_value=conn) as factory,mock.patch.object(admin,'get',return_value=metadata) as get:
            result=admin.dispatch()
        factory.assert_called_once();conn.request.assert_called_once()
        args=conn.request.call_args.args;self.assertEqual(args[:2],('POST','/deployments'));self.assertEqual(json.loads(args[2]),{'uri':'http://127.0.0.1:9085','force':False,'breaking':False})
        get.assert_called_once_with('/deployments/dp_Test1');self.assertEqual(result['deployment_id'],'dp_Test1');conn.close.assert_called_once()
    def test_timeout_is_unknown_and_never_retries(self):
        conn=mock.Mock();conn.request.side_effect=TimeoutError()
        with mock.patch.object(admin,'Connection',return_value=conn) as factory,mock.patch.object(admin,'get') as get:
            with self.assertRaises(TimeoutError):admin.dispatch()
        factory.assert_called_once();conn.request.assert_called_once();conn.close.assert_called_once();get.assert_not_called()
    def test_reconciliation_requires_unique_uri_and_full_service_set(self):
        entry={'id':'dp_Test1','uri':admin.URI}
        correct={'id':'dp_Test1','uri':admin.URI,'services':[{'name':x} for x in admin.SERVICES]}
        with mock.patch.object(admin,'get',side_effect=[{'deployments':[entry]},correct]):self.assertEqual(admin.reconcile()['deployment_id'],'dp_Test1')
        for values in ([{'deployments':[entry,entry]}],[{'deployments':[entry]},{**correct,'services':correct['services'][:-1]}],[{'deployments':[]}]):
            with self.subTest(values=values),mock.patch.object(admin,'get',side_effect=values),self.assertRaises(RuntimeError):admin.reconcile()
    def test_prezero_refuses_existing_uri_and_duplicate_json(self):
        with mock.patch.object(admin,'get',return_value={'deployments':[{'id':'dp_Test1','uri':admin.URI}]}):
            with self.assertRaises(RuntimeError):admin.prezero()
        with self.assertRaises(RuntimeError):admin.parse(b'{"id":"a","id":"b"}')
        with mock.patch.object(admin,'get',return_value={'deployments':[{'id':'dp_Test1','uri':admin.URI+'////'}]}):
            with self.assertRaises(RuntimeError):admin.prezero()
if __name__=='__main__':unittest.main()
