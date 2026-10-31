import contextlib,io,json,unittest
from unittest import mock
import nuc_unix_admin_h2_recovery_lost_ops as helper
STATUS='NoNewPrivs:\t1\n'+''.join('Cap'+n+':\t0000000000000000\n' for n in ('Inh','Prm','Eff','Bnd','Amb'))
class LostAck(unittest.TestCase):
 def run_case(self,failure=False):
  conn=mock.Mock();conn.getresponse.return_value.read.return_value=b'{"id":"dp_Private"}'
  if failure:conn.getresponse.side_effect=OSError('transport')
  with contextlib.ExitStack() as s:
   for name in ('getuid','geteuid','getgid','getegid'):s.enter_context(mock.patch.object(helper.os,name,return_value=2004))
   s.enter_context(mock.patch.object(helper.pathlib.Path,'read_text',return_value=STATUS));s.enter_context(mock.patch.object(helper,'Connection',return_value=conn));s.enter_context(mock.patch.object(helper.sys,'argv',['fixed']))
   out=s.enter_context(contextlib.redirect_stdout(io.StringIO()));helper.main()
  self.assertEqual(out.getvalue(),'DISPATCHED_RESPONSE_UNKNOWN\n');conn.request.assert_called_once();conn.close.assert_called_once()
  args=conn.request.call_args.args;self.assertEqual(args[:2],('POST','/deployments'));self.assertEqual(json.loads(args[2]),{'uri':'http://127.0.0.1:9086','force':False,'breaking':False})
  return conn
 def test_drains_upstream_but_discards_ack(self):self.run_case().getresponse.return_value.read.assert_called_once_with(65537)
 def test_transport_error_is_same_unknown_without_retry(self):self.run_case(True)
