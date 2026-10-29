import os,pathlib,tempfile,unittest
from nuc_response_capture import ResponseCapture
from nuc_bifrost_pinned_exec import PinnedDockerTransport
from nuc_bifrost_live_transport import TransportRefused
class Tests(unittest.TestCase):
 def test_exact_private_capture_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as root:
   cap=ResponseCapture(root);cap(b'data');cap.close();p=pathlib.Path(root)/'provider-body-0.bin'
   self.assertEqual(p.read_bytes(),b'data');self.assertEqual(p.stat().st_mode&0o777,0o600)
   cap=ResponseCapture(root)
   with self.assertRaises(FileExistsError):cap(b'different')
   cap.close();self.assertEqual(p.read_bytes(),b'data')
 def test_transport_captures_exact_body_before_return(self):
  p=object.__new__(PinnedDockerTransport);p._credential='not-in-body';p.trace=None;events=[];p.capture=events.append
  body=b'data: [DONE]\n\n';raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body;p._exchange=lambda _:raw
  self.assertEqual(p.send({'model':'auto'}),body);self.assertEqual(events,[body])
 def test_credential_containing_response_never_captured(self):
  p=object.__new__(PinnedDockerTransport);p._credential='secret-value';p.trace=None;events=[];p.capture=events.append
  body=b'data: secret-value\n\n';raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body;p._exchange=lambda _:raw
  with self.assertRaises(TransportRefused):p.send({'model':'auto'})
  self.assertEqual(events,[])
