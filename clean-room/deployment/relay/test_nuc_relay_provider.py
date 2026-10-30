import email.message
import os
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from nuc_relay_authority import Denied
from nuc_relay_provider import LoopbackProvider

class Response:
    def __init__(self, data=b'data: [DONE]\n\n', status=200, extra=()):
        self.status=status;self.data=data;self.headers=email.message.Message()
        self.headers['Content-Type']='text/event-stream'
        self.headers['Content-Length']=str(len(data))
        for k,v in extra:self.headers[k]=v
    def read(self, limit):return self.data[:limit]

class Transport(unittest.TestCase):
    def test_real_loopback_chunked_framing_with_synthetic_key(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1];requests=[]
        def fixture():
            conn,_=listener.accept()
            with conn:
                conn.settimeout(2);raw=bytearray()
                while b'\r\n\r\n' not in raw:raw.extend(conn.recv(4096))
                header,body=bytes(raw).split(b'\r\n\r\n',1)
                length=int(next(line.split(b':',1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                while len(body)<length:body+=conn.recv(4096)
                requests.append((header,body))
                payload=b'data: [DONE]\n\n'
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n'+f'{len(payload):x}'.encode()+b'\r\n'+payload+b'\r\n0\r\n\r\n')
        thread=threading.Thread(target=fixture);thread.start()
        from nuc_relay_provider import http
        real=http.client.HTTPConnection
        def connect(host,requested_port,timeout):
            self.assertEqual((host,requested_port),('127.0.0.1',8080))
            return real('127.0.0.1',port,timeout=timeout)
        try:
            with tempfile.TemporaryFile() as key:
                key.write(b'synthetic-test-key');key.flush()
                with patch('nuc_relay_provider.validate_provider_descriptor'),patch('nuc_relay_provider.check_namespace'),patch('nuc_relay_provider.http.client.HTTPConnection',connect):
                    provider=LoopbackProvider({},key.fileno())
                    try:self.assertEqual(provider.send({'model':'auto'}),b'data: [DONE]\n\n')
                    finally:os.close(provider.credential_fd)
            thread.join(timeout=3);self.assertFalse(thread.is_alive());self.assertEqual(len(requests),1)
            self.assertIn(b'POST /v1/chat/completions HTTP/1.1',requests[0][0])
        finally:listener.close()
    def test_fixed_endpoint_and_synthetic_secret_never_in_reply(self):
        calls=[]
        class Conn:
            def __init__(self,host,port,timeout):calls.append((host,port,timeout))
            def request(self,method,path,body,headers):
                calls.append((method,path,headers['x-bf-vk']))
            def getresponse(self):return Response()
            def close(self):pass
        with tempfile.TemporaryFile() as key:
            key.write(b'synthetic-test-key');key.flush()
            with patch('nuc_relay_provider.validate_provider_descriptor'), patch('nuc_relay_provider.check_namespace'), patch('nuc_relay_provider.http.client.HTTPConnection',Conn):
                provider=LoopbackProvider({},key.fileno())
                try:
                    self.assertEqual(provider.send({'model':'auto','messages':[]}),b'data: [DONE]\n\n')
                    self.assertEqual(calls,[('127.0.0.1',8080,65),('POST','/v1/chat/completions','synthetic-test-key')])
                    with self.assertRaises(Denied):provider.send({'model':'unreviewed'})
                    with self.assertRaises(Denied):provider.send({'model':'auto','messages':['synthetic-test-key']})
                finally:os.close(provider.credential_fd)

    def test_ambiguous_framing_and_echoed_key_fail_closed(self):
        current=[]
        class Conn:
            def __init__(self,*args,**kwargs):pass
            def request(self,*args,**kwargs):pass
            def getresponse(self):return current[0]
            def close(self):pass
        with tempfile.TemporaryFile() as key:
            key.write(b'synthetic-test-key');key.flush()
            with patch('nuc_relay_provider.validate_provider_descriptor'), patch('nuc_relay_provider.check_namespace'), patch('nuc_relay_provider.http.client.HTTPConnection',Conn):
                provider=LoopbackProvider({},key.fileno())
                try:
                    for response in [Response(extra=[('Transfer-Encoding','chunked')]),Response(extra=[('Content-Length','2')]),Response(b'synthetic-test-key'),Response(status=302)]:
                        current[:]=[response]
                        with self.assertRaises(Denied):provider.send({'model':'auto'})
                finally:os.close(provider.credential_fd)

if __name__=='__main__':unittest.main()
