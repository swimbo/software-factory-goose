import io,json,unittest
from unittest.mock import patch
import nuc_registry_drain_probe as m
class Drain(unittest.TestCase):
 def test_bad_ids_denied_before_network(self):
  fake=type('I',(),{'buffer':io.BytesIO(json.dumps({'schema':1,'deployment_ids':["dp_x' OR 1=1"]}).encode())})()
  status=io.StringIO('NoNewPrivs:\t1\n'+''.join('Cap'+x+':\t0000000000000000\n' for x in ('Inh','Prm','Eff','Bnd','Amb')))
  with patch.object(m.os,'getuid',return_value=2000),patch.object(m.os,'geteuid',return_value=2000),patch.object(m.os,'getgid',return_value=2000),patch.object(m.os,'getegid',return_value=2000),patch('builtins.open',return_value=status),patch.object(m.sys,'stdin',fake),patch.object(m.http.client,'HTTPConnection') as conn:
   with self.assertRaisesRegex(RuntimeError,'invalid deployments'):m.main()
   conn.assert_not_called()
if __name__=='__main__':unittest.main()
