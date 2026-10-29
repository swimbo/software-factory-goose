import base64
import json
import unittest

from nuc_bifrost_live_transport import TransportRefused
from nuc_bifrost_pinned_exec import IncrementalFramer, complete_http, parse_http
from nuc_stream_contract import RAW_SSE_BYTES, PROVIDER_WIRE_BYTES, RELAY_REPLY_BYTES


class StreamBoundaries(unittest.TestCase):
    def test_exact_raw_boundary_and_first_overflow(self):
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '
        body = b'x' * RAW_SSE_BYTES
        wire = header + str(len(body)).encode() + b'\r\n\r\n' + body
        self.assertTrue(complete_http(wire))
        self.assertEqual(len(parse_http(wire)), RAW_SSE_BYTES)
        extra = body + b'x'
        too_large = header + str(len(extra)).encode() + b'\r\n\r\n' + extra
        self.assertFalse(complete_http(too_large))
        with self.assertRaises(TransportRefused):
            parse_http(too_large)

    def test_chunked_fragmentation_and_malformed_endings(self):
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'
        part = b'1000\r\n' + b'x' * 4096 + b'\r\n'
        wire = header + part * (RAW_SSE_BYTES // 4096) + b'0\r\n\r\n'
        framer = IncrementalFramer()
        current = bytearray()
        for start in range(0, len(wire), 16384):
            current.extend(wire[start:start + 16384])
            complete = framer.feed(current)
            if len(current) < len(wire):
                self.assertFalse(complete)
        self.assertTrue(complete)
        self.assertTrue(complete_http(bytes(current)))
        self.assertFalse(complete_http(wire[:-1]))
        self.assertFalse(complete_http(wire + b'x'))
        self.assertFalse(complete_http(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n'))

    def test_transport_budgets_include_outer_envelopes(self):
        encoded = base64.b64encode(b'x' * RAW_SSE_BYTES).decode('ascii')
        reply = json.dumps({'ok': True, 'value': encoded}, separators=(',', ':')).encode()
        self.assertLessEqual(len(reply), RELAY_REPLY_BYTES)
        self.assertLess(RAW_SSE_BYTES, PROVIDER_WIRE_BYTES)
        oversized = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' + b'x' * PROVIDER_WIRE_BYTES
        self.assertFalse(complete_http(oversized))


if __name__ == '__main__':
    unittest.main()
