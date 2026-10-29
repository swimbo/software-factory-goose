import unittest,sys
from unittest.mock import patch
from nuc_bifrost_pinned_exec import parse_http,complete_http,response_metadata,PinnedDockerTransport
from nuc_bifrost_live_transport import TransportRefused
class Tests(unittest.TestCase):
 def test_bounded_http_and_chunked(self):
  body=b'data: [DONE]\n\n'
  raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'+hex(len(body))[2:].encode()+b'\r\n'+body+b'\r\n0\r\n\r\n'
  self.assertEqual(parse_http(raw),body)
 def test_completion_requires_complete_response_framing(self):
  raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n'
  self.assertFalse(complete_http(raw[:-3]));self.assertTrue(complete_http(raw))
  length=b'HTTP/1.1 400 Bad\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
  self.assertFalse(complete_http(length[:-1]));self.assertTrue(complete_http(length))
  close=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: [DONE]\n\n'
  self.assertTrue(complete_http(close));self.assertFalse(complete_http(close[:-1]))
 def test_framing_rejects_incomplete_headers_extra_bytes_and_ambiguous_lengths(self):
  for raw in (b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\ndata: [DONE]\n\n',b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n'):
   self.assertFalse(complete_http(raw))
 def test_failure_exposes_only_safe_status_metadata(self):
  raw=b'HTTP/1.0 401 Nope\r\nContent-Type: application/json\r\nX-Request-Id: abcdef0123456789\r\n\r\nsecret body'
  with self.assertRaisesRegex(TransportRefused,'status=401 content_type=application/json request_id=abcdef0123456789') as error:parse_http(raw)
  self.assertNotIn('secret',str(error.exception))
 def test_parse_sse_rejects_bytes_after_declared_length(self):
  raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1\r\n\r\nxy'
  with self.assertRaises(TransportRefused):parse_http(raw)
 def test_spawn_failure_reports_only_fixed_category(self):
  p=object.__new__(PinnedDockerTransport);p._docker=['docker'];p.container_id='x';p._env={};p._identity=lambda:None
  with patch('nuc_bifrost_pinned_exec.subprocess.Popen',side_effect=OSError('secret stderr')):
   with self.assertRaises(TransportRefused) as error:p._exchange(b'credential')
  self.assertIn('stage=spawn',str(error.exception));self.assertIn('response_bytes=0',str(error.exception));self.assertNotIn('secret',str(error.exception));self.assertNotIn('credential',str(error.exception))
 def test_child_failure_reports_length_and_framing_without_content(self):
  p=object.__new__(PinnedDockerTransport);p._identity=lambda:None;p.container_id='x';p._env={}
  program="import os,sys; os.read(0,6); os.write(1,b'HTTP/1.1 400 Bad\\r\\nContent-Length: 6\\r\\n\\r\\nsecret'); sys.exit(1)"
  p._docker=[sys.executable,'-c',program]
  with self.assertRaises(TransportRefused) as error:p._exchange(b'abcdef')
  self.assertIn('stage=child_exit',str(error.exception));self.assertIn('framing=complete',str(error.exception));self.assertNotIn('secret',str(error.exception))
 def test_fragmented_stream_stays_open_until_complete(self):
  p=object.__new__(PinnedDockerTransport);p._identity=lambda:None;p.container_id='x';p._env={}
  program="import os,time; os.read(0,6); os.write(1,b'HTTP/1.1 200 OK\\r\\nContent-Type: text/event-stream\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n'); body=b'x'*16000; os.write(1,hex(len(body))[2:].encode()+b'\\r\\n'+body+b'\\r\\n'); time.sleep(.05); os.write(1,b'0\\r\\n\\r\\n')"
  p._docker=[sys.executable,'-c',program]
  result=p._exchange(b'abcdef');self.assertTrue(complete_http(result));self.assertEqual(len(parse_http(result)),16000)
 def test_trace_has_only_bounded_http_metadata(self):
  raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\nX-Secret: credential\r\n\r\nprivate body'
  events=[];p=object.__new__(PinnedDockerTransport);p.trace=events.append;p._credential='secret';p._exchange=lambda _:raw
  with self.assertRaises(TransportRefused):p.send({'model':'auto'})
  self.assertEqual(events[0]['event'],'parse_failed');self.assertEqual(events[0]['status'],200);self.assertEqual(events[0]['content_length'],100);self.assertFalse(events[0]['framing_complete']);self.assertNotIn('private',str(events));self.assertNotIn('credential',str(events));self.assertNotIn('secret',str(events))
 def test_trace_records_framing_before_close_and_child_exit(self):
  p=object.__new__(PinnedDockerTransport);p._identity=lambda:None;p.container_id='x';p._env={};events=[];p.trace=events.append
  program="import os; os.read(0,6); os.write(1,b'HTTP/1.1 200 OK\\r\\nContent-Type: text/event-stream\\r\\nContent-Length: 6\\r\\n\\r\\nsecret')"
  p._docker=[sys.executable,'-c',program];p._exchange(b'abcdef')
  self.assertEqual([e['event'] for e in events],['framing_complete_before_close','child_exit']);self.assertEqual(events[-1]['child_exit'],0);self.assertNotIn('secret',str(events))
 def test_bad_http_and_truncated_chunk_fail_closed(self):
  for raw in [b'HTTP/1.0 401 Nope\r\n\r\nsecret',b'HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\nx',b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nx',b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nx']:
   with self.assertRaises(TransportRefused):parse_http(raw)
if __name__=='__main__':unittest.main()
