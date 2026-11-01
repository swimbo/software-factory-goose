import importlib.util,pathlib,struct,unittest
from unittest import mock
spec=importlib.util.spec_from_file_location('diagspike',pathlib.Path(__file__).with_name('nuc_unixdiag_peer_spike.py'));spike=importlib.util.module_from_spec(spec);spec.loader.exec_module(spike)
def msg(kind,payload=b''):
 length=16+len(payload);return struct.pack('=IHHII',length,kind,2,0x53464143,0)+payload+b'\0'*((-length)%4)
def item(inode,peer):
 body=struct.pack('=BBBBIII',1,1,1,0,inode,0,0)+struct.pack('=HHI',8,2,peer)
 return msg(20,body)
class FakeSocket:
 def __init__(self,sender):self.sender=sender
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def settimeout(self,*args):pass
 def bind(self,*args):pass
 def send(self,*args):pass
 def recvmsg(self,*args):return item(100,200)+item(200,100)+msg(3),[],0,(self.sender,0)
class UnixDiagTests(unittest.TestCase):
 def test_bidirectional_mapping(self):
  with mock.patch.object(spike.socket,'AF_NETLINK',16,create=True),mock.patch.object(spike.socket,'socket',return_value=FakeSocket(0)):
   self.assertEqual(spike.diag(),{100:(200,None),200:(100,None)})
 def test_userspace_sender_rejected(self):
  with mock.patch.object(spike.socket,'AF_NETLINK',16,create=True),mock.patch.object(spike.socket,'socket',return_value=FakeSocket(111)):
   with self.assertRaisesRegex(RuntimeError,'non-kernel'):spike.diag()
if __name__=='__main__':unittest.main()
