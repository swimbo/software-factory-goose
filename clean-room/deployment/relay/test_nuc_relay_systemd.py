import json
import socket
import threading
import unittest
from unittest.mock import patch
from nuc_relay_authority import Denied
from nuc_relay_systemd import named_descriptors, serve_connection

class SystemdBoundary(unittest.TestCase):
    def test_descriptor_names_define_mapping_not_order(self):
        env={'LISTEN_PID':'123','LISTEN_FDS':'6','LISTEN_FDNAMES':'provider:callback:consumed:scope:catalog:provider-binding'}
        self.assertEqual(named_descriptors(env,123),{'provider':3,'callback':4,'consumed':5,'scope':6,'catalog':7,'provider-binding':8})
        for changed in [dict(env,LISTEN_PID='124'),dict(env,LISTEN_FDS='5'),
                        dict(env,LISTEN_FDNAMES='scope:scope:consumed:provider:callback:provider-binding')]:
            with self.assertRaises(Denied):named_descriptors(changed,123)

    def run_frame(self, payload):
        a,b=socket.socketpair(); result=[]
        class Core:
            def call(self,conn,value):result.append(value);return 'synthetic'
        def server():
            try:
                with patch('nuc_relay_systemd.require_worker_peer'):
                    serve_connection(a,Core())
            except Denied:result.append('denied')
            finally:a.close()
        t=threading.Thread(target=server);t.start()
        try:
            try:b.sendall(payload);b.shutdown(socket.SHUT_WR)
            except OSError:pass  # Oversize refusal may close while the sender is writing.
            try:output=b.recv(4096)
            except OSError:output=b''
            t.join(timeout=3);self.assertFalse(t.is_alive());return result,output
        finally:b.close()

    def test_socket_frame_and_reply(self):
        result,out=self.run_frame(b'{"type":"inference","body":{}}\n')
        self.assertEqual(result,[{'type':'inference','body':{}}])
        self.assertEqual(json.loads(out),{'ok':True,'value':'synthetic'})
    def test_duplicate_or_concatenated_frames_never_reach_core(self):
        for frame in [b'{"type":"x","type":"y"}\n', b'{}\n{}\n',b'x'*65537+b'\n']:
            result,_=self.run_frame(frame);self.assertEqual(result,['denied'])

if __name__=='__main__':unittest.main()
