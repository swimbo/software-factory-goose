import base64,json,unittest,tempfile
from nuc_stream_contract import RAW_SSE_BYTES,PROVIDER_WIRE_BYTES,RELAY_REPLY_BYTES,REQUEST_FRAME_BYTES,reply_fits,RELAY_READ_TIMEOUT_SECONDS
from nuc_bifrost_pinned_exec import parse_http,complete_http,IncrementalFramer
from nuc_bifrost_live_transport import TransportRefused
from nuc_goose_relay_socket import send_reply
from trusted_tool_relay import Refused
from nuc_file_contract import MAX_ARGUMENT_BYTES
from nuc_run_fence import RunFence,Denied
class Tests(unittest.TestCase):
 def test_raw_response_exact_and_over(self):
  for n in (RAW_SSE_BYTES,RAW_SSE_BYTES+1):
   body=b'x'*n;raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '+str(n).encode()+b'\r\n\r\n'+body
   if n==RAW_SSE_BYTES:self.assertEqual(len(parse_http(raw)),n)
   else:
    with self.assertRaises(TransportRefused):parse_http(raw)
 def test_fence_accepts_exact_stream_and_rejects_over(self):
  with tempfile.TemporaryDirectory() as root:
   f=RunFence(root,'run','task',create=True);call=f.begin_inference(0,b'request')
   with self.assertRaises(Denied):f.record_tool(call,b'x'*(RAW_SSE_BYTES+1),'id',{})
   f.record_tool(call,b'x'*RAW_SSE_BYTES,'id',{});self.assertEqual(f.read()['stage'],'tool_ready')
 def test_reply_serialized_and_frame_boundaries(self):
  encoded=json.dumps({'ok':True,'value':base64.b64encode(b'x'*RAW_SSE_BYTES).decode()},separators=(',',':')).encode()
  self.assertTrue(reply_fits(len(encoded)));self.assertTrue(reply_fits(RELAY_REPLY_BYTES));self.assertFalse(reply_fits(RELAY_REPLY_BYTES+1))
  self.assertEqual(REQUEST_FRAME_BYTES,65536);self.assertEqual(MAX_ARGUMENT_BYTES,12288);self.assertEqual(RELAY_READ_TIMEOUT_SECONDS,90)
 def test_actual_serialized_reply_exact_and_over(self):
  class Sink:
   def __init__(self):self.count=0
   def sendall(self,value):self.count+=len(value)
  overhead=len(json.dumps({'ok':True,'value':''},separators=(',',':')).encode());sink=Sink()
  send_reply(sink,'x'*(RELAY_REPLY_BYTES-overhead));self.assertEqual(sink.count,RELAY_REPLY_BYTES)
  sink=Sink()
  with self.assertRaises(Refused):send_reply(sink,'x'*(RELAY_REPLY_BYTES-overhead+1))
  self.assertEqual(sink.count,0)
 def test_exact_provider_wire_and_one_byte_over(self):
  head=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n';tail=b'0\r\n\r\n';pad=len(head)+len(tail)
  def chunk(n):return b'100;'+b'a'*n+b'\r\n'+b'x'*256+b'\r\n'
  wire=head+chunk(120-pad)+chunk(120)*32767+tail
  self.assertEqual(len(wire),PROVIDER_WIRE_BYTES);self.assertTrue(complete_http(wire));self.assertFalse(complete_http(wire+b'x'))
 def test_wire_and_incremental_framing_exact(self):
  self.assertFalse(complete_http(b'x'*(PROVIDER_WIRE_BYTES+1)))
  raw=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n';f=IncrementalFramer();out=bytearray()
  for b in raw:out.append(b);complete=f.feed(out)
  self.assertTrue(complete);self.assertTrue(complete_http(bytes(out)))
  out.extend(b'x');self.assertFalse(f.feed(out))
