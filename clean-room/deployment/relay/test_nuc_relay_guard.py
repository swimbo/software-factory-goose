import json
import struct
import unittest
from unittest.mock import patch
from nuc_relay_authority import Denied
from nuc_relay_guard import RootGuard
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
SCOPE={'generation':G,'grant_sha256':'a'*64,'catalog_sha256':'b'*64,'provider_binding_sha256':'c'*64}
BINDING={'network_device':1,'network_inode':2}

class Fake:
    def __init__(self,uid,reply):self.uid=uid;self.reply=reply;self.sent=[]
    def settimeout(self,_):pass
    def connect(self,path):self.path=path
    def getsockopt(self,*args):return struct.pack('3i',123,self.uid,0)
    def sendall(self,frame):self.sent.append(frame)
    def recv(self,_):return json.dumps(self.reply).encode()+b'\n'
    def close(self):pass
class Guard(unittest.TestCase):
    def test_exact_root_attestation_required(self):
        guard=RootGuard(SCOPE,BINDING)
        for uid,reply,accepted in [(0,guard.expected,True),(2000,guard.expected,False),
                                   (0,{**guard.expected,'grant_sha256':'d'*64},False),
                                   (0,{**guard.expected,'open':1},False)]:
            fake=Fake(uid,reply)
            with patch.object(guard,'_verify_path'),patch('nuc_relay_guard.socket.socket',return_value=fake),patch('nuc_relay_guard.socket.SO_PEERCRED',17,create=True):
                if accepted:self.assertIs(guard.check(SCOPE),True)
                else:
                    with self.assertRaises(Denied):guard.check(SCOPE)
            if uid==0:self.assertEqual(fake.sent,[b'{"op":"guard"}\n'])
            else:self.assertEqual(fake.sent,[])

if __name__=='__main__':unittest.main()
