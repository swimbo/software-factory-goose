import os,pathlib,sys,tempfile,unittest
from nuc_bifrost_live_transport import BifrostTransport,TransportRefused

class TransportTests(unittest.TestCase):
 def test_unverified_tcp_never_sends(self):
  with tempfile.TemporaryDirectory(dir=os.path.expanduser('~') if sys.platform=='linux' else None) as d:
   key=os.path.join(os.path.realpath(d),'key');pathlib.Path(key).write_bytes(b'fixture-secret');os.chmod(key,0o600)
   t=BifrostTransport(key)
   with self.assertRaisesRegex(TransportRefused,'unverified provider endpoint'):t.send({'model':'auto'})
 def test_bad_file_mode_and_symlink_denied(self):
  with tempfile.TemporaryDirectory(dir=os.path.expanduser('~') if sys.platform=='linux' else None) as d:
   p=os.path.join(os.path.realpath(d),'key');pathlib.Path(p).write_bytes(b'fixture-secret');os.chmod(p,0o644)
   with self.assertRaises(TransportRefused):BifrostTransport(p)
   link=os.path.join(os.path.realpath(d),'link');os.symlink(p,link)
   with self.assertRaises(TransportRefused):BifrostTransport(link)
if __name__=='__main__':unittest.main()
