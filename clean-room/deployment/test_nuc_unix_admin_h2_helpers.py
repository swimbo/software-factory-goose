import contextlib,io,json,pathlib,unittest
from unittest import mock
import nuc_unix_admin_h2_fixed_ops as admin
import nuc_unix_admin_h2_lost_ops as lost
import nuc_unix_admin_h2_helpers_install as install
STATUS='NoNewPrivs:\t1\n'+''.join('Cap'+n+':\t0000000000000000\n' for n in ('Inh','Prm','Eff','Bnd','Amb'))
class Helpers(unittest.TestCase):
 def identity(self,mod):
  stack=contextlib.ExitStack()
  for key in ('getuid','geteuid','getgid','getegid'):stack.enter_context(mock.patch.object(mod.os,key,return_value=2004))
  stack.enter_context(mock.patch('builtins.open',mock.mock_open(read_data=STATUS)))
  return stack
 def test_registration_is_fixed_nonforcing_and_single_post(self):
  calls=[];responses=[(201,{'id':'dp_Test','services':[{'name':'FenceFixture'}]}),(200,{'id':'dp_Test','uri':'http://127.0.0.1:9081','services':[{'name':'FenceFixture'}]})]
  class Conn:
   def __init__(self,*a,**kw):pass
   def request(self,*args,**kw):calls.append((args,kw))
   def getresponse(self):
    status,body=responses.pop(0)
    return type('Response',(),{'status':status,'read':lambda self,n:json.dumps(body).encode()})()
   def close(self):pass
  with self.identity(admin),mock.patch.object(admin,'Connection',Conn),mock.patch.object(admin.sys,'argv',['fixed','register-old']),contextlib.redirect_stdout(io.StringIO()) as out:admin.main()
  self.assertEqual([x[0][0] for x in calls],['POST','GET'])
  self.assertEqual(json.loads(calls[0][0][2]),{'uri':'http://127.0.0.1:9081','force':False,'breaking':False})
  self.assertEqual(json.loads(out.getvalue())['deployment_id'],'dp_Test')
 def test_lost_reply_sends_once_without_read_or_retry(self):
  conn=mock.Mock();conn.recv.side_effect=AssertionError('must not read')
  with self.identity(lost),mock.patch.object(lost.socket,'socket',return_value=conn),contextlib.redirect_stdout(io.StringIO()):lost.main()
  conn.connect.assert_called_once_with('/var/lib/software-factory-goose/unix-admin-h2-canary/data/sfactory-unix-admin-h2/admin.sock');conn.sendall.assert_called_once();conn.recv.assert_not_called();conn.close.assert_called_once()
  self.assertIn(b'"force":false,"breaking":false',conn.sendall.call_args.args[0])
 def test_installer_pins_distinct_sources(self):
  import hashlib
  for name,pin in [('nuc_unix_admin_h2_fixed_ops.py',install.ADMIN_SHA),('nuc_unix_admin_h2_snapshot_ops.py',install.OPS_SHA),('nuc_unix_admin_h2_lost_ops.py',install.LOST_SHA)]:
   raw=pathlib.Path(__file__).with_name(name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),pin)
  self.assertIn('unix-admin-h2-canary',str(install.DEST));self.assertNotEqual(admin.SOCKET,'/var/lib/software-factory-goose/unix-admin-canary/data/sfactory-unix-admin/admin.sock')
