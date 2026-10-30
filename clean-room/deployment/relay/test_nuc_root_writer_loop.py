import json
import os
import pathlib
import signal
import stat
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import nuc_fixed_writer as writer
import nuc_root_writer_broker as broker
from nuc_relay_authority import Denied
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
FILES={'files':{'hello.py':'print("hello")\n','test_hello.py':'assert True\n'}}
class Authority:
    def __init__(self):self.open=True
    def verify(self):
        if not self.open:raise Denied('closed')
        return {'open':True}
    def check_stop(self):
        if not self.open:raise Denied('closed')

class Handoff(unittest.TestCase):
    def test_generation_cannot_select_paths(self):
        with self.assertRaises(Denied):broker.WriterBroker('../escape',Authority(),0,0,0)
    def dirs(self,root):
        paths=[pathlib.Path(root)/x for x in ('state','input','output','candidate')]
        for path in paths:path.mkdir()
        return paths,[os.open(path,os.O_RDONLY|os.O_DIRECTORY) for path in paths]
    def test_real_files_and_fixed_writer_once(self):
        with tempfile.TemporaryDirectory() as root:
            paths,fds=self.dirs(root);original=os.fstat;errors=[]
            def fake(fd):
                st=original(fd)
                if not stat.S_ISREG(st.st_mode):return st
                result=paths[2]/'result.json'
                owner=2001 if result.exists() and result.stat().st_ino==st.st_ino else 0
                return SimpleNamespace(st_mode=st.st_mode,st_uid=owner,st_gid=owner,st_nlink=st.st_nlink,st_size=st.st_size)
            def worker():
                try:
                    until=time.monotonic()+3
                    while not (paths[1]/'ready').exists():
                        if time.monotonic()>until:raise RuntimeError('no ready')
                        time.sleep(.005)
                    writer.run_once(fds[1],fds[2],fds[3])
                except Exception as exc:errors.append(exc)
            try:
                with patch.object(os,'fstat',side_effect=fake):
                    b=broker.WriterBroker(G,Authority(),fds[0],fds[1],fds[2]);t=threading.Thread(target=worker);t.start()
                    result=b.write_files(FILES);t.join(timeout=3)
                    self.assertFalse(t.is_alive());self.assertEqual(errors,[])
                    self.assertEqual(result['status'],'executed')
                    for name,text in FILES['files'].items():self.assertEqual((paths[3]/name).read_text(),text)
                    with self.assertRaises(Denied):b.write_files(FILES)
                    self.assertEqual(set(p.name for p in paths[3].iterdir()),{'hello.py','test_hello.py'})
            finally:
                for fd in fds:os.close(fd)
    def test_stop_after_intent_keeps_partial_state_and_never_retries(self):
        with tempfile.TemporaryDirectory() as root:
            paths,fds=self.dirs(root)
            class Stops(Authority):
                def __init__(self):super().__init__();self.n=0
                def verify(self):
                    self.n+=1
                    if self.n==2:self.open=False
                    return super().verify()
            try:
                b=broker.WriterBroker(G,Stops(),fds[0],fds[1],fds[2])
                with self.assertRaises(Denied):b.write_files(FILES)
                self.assertTrue((paths[0]/(G+'.writer-intent')).exists())
                self.assertFalse((paths[1]/'ready').exists())
                with self.assertRaises(Denied):broker.WriterBroker(G,Authority(),fds[0],fds[1],fds[2]).write_files(FILES)
            finally:
                for fd in fds:os.close(fd)

    @unittest.skipUnless(hasattr(os,'fork'),'requires POSIX process')
    def test_broker_sigkill_after_request_never_republishes(self):
        with tempfile.TemporaryDirectory() as root:
            paths,fds=self.dirs(root)
            class KillAfterRequest(Authority):
                def __init__(self):super().__init__();self.n=0
                def verify(self):
                    self.n+=1
                    if self.n==3:os.kill(os.getpid(),signal.SIGKILL)
                    return super().verify()
            try:
                pid=os.fork()
                if pid==0:
                    try:broker.WriterBroker(G,KillAfterRequest(),fds[0],fds[1],fds[2]).write_files(FILES)
                    finally:os._exit(99)
                _,status=os.waitpid(pid,0)
                self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                self.assertTrue((paths[0]/(G+'.writer-intent')).exists())
                self.assertTrue((paths[1]/'request.json').exists());self.assertFalse((paths[1]/'ready').exists())
                with self.assertRaises(Denied):broker.WriterBroker(G,Authority(),fds[0],fds[1],fds[2]).write_files(FILES)
                self.assertFalse((paths[1]/'ready').exists())
            finally:
                for fd in fds:os.close(fd)

if __name__=='__main__':unittest.main()
