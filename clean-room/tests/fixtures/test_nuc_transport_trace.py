import json,os,tempfile,unittest,pathlib
from nuc_transport_trace import TransportTrace
class Tests(unittest.TestCase):
 def test_private_bounded_metadata_only(self):
  with tempfile.TemporaryDirectory() as root:
   t=TransportTrace(root);event={'wire_bytes':42,'framing_complete':False,'version':'1.1','status':200,'content_type':'text/event-stream','content_length':None,'transfer_encoding':'chunked','event':'failure_read','child_exit':None}
   t(event)
   with self.assertRaises(RuntimeError):t({**event,'body':'secret'})
   t.close();path=os.path.join(root,'transport-trace.jsonl');self.assertEqual(os.stat(path).st_mode&0o777,0o600);self.assertEqual(json.loads(pathlib.Path(path).read_text()),event)
   with self.assertRaises(FileExistsError):TransportTrace(root)
