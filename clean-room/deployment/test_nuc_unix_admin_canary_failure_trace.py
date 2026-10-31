import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_unix_admin_canary_failure_trace as trace
class TraceTests(unittest.TestCase):
 def test_only_fixed_probe_frame_metadata_is_extracted(self):
  data=b'  File "/secret/other.py", line 9, in other\n  File "/usr/local/unix-admin-canary-ingress-probe-v2.py", line 50, in main\nraw secret body not output\n  File "/usr/local/unix-admin-canary-ingress-probe-v2.py", line 14, in response\n'
  self.assertEqual(trace.extract_frames(data),[{'line':50,'function':'main'},{'line':14,'function':'response'}])
 def test_unbounded_frame_count_denied(self):
  with self.assertRaises(RuntimeError):trace.extract_frames(b'  File "/x/unix-admin-canary-ingress-probe-v2.py", line 1, in main\n'*17)
if __name__=='__main__':unittest.main()
