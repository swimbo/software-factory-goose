import json
import struct
import unittest
from unittest.mock import patch
from nuc_relay_authority import Denied
from nuc_relay_writer import RootWriter
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
ARGS={'files':{'hello.py':'x','test_hello.py':'y'}}

class Fake:
    def __init__(self, uid):self.uid=uid;self.sent=[];self.path=None
    def settimeout(self,_):pass
    def connect(self,path):self.path=path
    def getsockopt(self,*args):return struct.pack('3i',123,self.uid,0)
    def sendall(self,frame):self.sent.append(frame)
    def recv(self,_):return b'{"status":"executed","exit_code":0,"stdout":"Both task files written.","stderr":""}\n'
    def close(self):pass

class Writer(unittest.TestCase):
    def test_root_peer_and_fixed_generation_path(self):
        fake=Fake(0);writer=RootWriter({'generation':G})
        with patch.object(writer,'_verify_path'),patch('nuc_relay_writer.socket.socket',return_value=fake), patch('nuc_relay_writer.socket.SO_PEERCRED',17,create=True):
            self.assertEqual(writer.execute(ARGS)['status'],'executed')
        self.assertEqual(fake.path,'/run/software-factory-goose/writer/'+G+'.sock')
        self.assertEqual(json.loads(fake.sent[0]),{'op':'write_files','files':ARGS['files']})
    def test_wrong_peer_or_extra_field_sends_nothing(self):
        for uid,args in [(2000,ARGS),(0,{**ARGS,'command':'id'})]:
            fake=Fake(uid);writer=RootWriter({'generation':G})
            with patch.object(writer,'_verify_path'),patch('nuc_relay_writer.socket.socket',return_value=fake),patch('nuc_relay_writer.socket.SO_PEERCRED',17,create=True):
                with self.assertRaises(Denied):writer.execute(args)
            self.assertEqual(fake.sent,[])

if __name__=='__main__':unittest.main()
