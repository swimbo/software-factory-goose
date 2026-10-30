import hashlib,importlib.util,json,os,pathlib,socket,subprocess,sys,tempfile,threading,unittest
p=pathlib.Path(__file__).with_name('nuc_private_runtime_acceptance.py')
spec=importlib.util.spec_from_file_location('acceptance',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_worker_reads_actual_chunked_http_without_printing_token(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=str(pathlib.Path(tmp)/'worker.sock');listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen()
   obj={'Assigned':{'work_package_id':m.TASK,'spec':{'repository':'fixture','base_revision':'a'*40},'lease':{'worker_id':'fixture-worker','attempt':1,'token':'private-test-token'}}}
   body=json.dumps(obj).encode()
   def server():
    stream,_=listener.accept()
    with stream:
     stream.recv(4096);stream.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'+f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n')
   thread=threading.Thread(target=server);thread.start()
   code=m.WORKER_CODE.replace("'/worker.sock'",repr(path))
   p=subprocess.run([sys.executable,'-I','-B','-c',code,str(os.geteuid()),'pull'],capture_output=True,timeout=5,check=True)
   thread.join();listener.close();out=json.loads(p.stdout)
   self.assertEqual(out['status'],200);self.assertNotIn(b'private-test-token',p.stdout)
   self.assertEqual(out['digest'],hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest())
 def test_worker_scope_mismatch_fails(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=str(pathlib.Path(tmp)/'worker.sock');listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen()
   body=json.dumps({'Assigned':{'work_package_id':'other','spec':{'repository':'fixture','base_revision':'a'*40},'lease':{'worker_id':'fixture-worker','attempt':1}}}).encode()
   def server():
    stream,_=listener.accept()
    with stream:stream.recv(4096);stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
   thread=threading.Thread(target=server);thread.start()
   code=m.WORKER_CODE.replace("'/worker.sock'",repr(path));p=subprocess.run([sys.executable,'-I','-B','-c',code,str(os.geteuid()),'pull'],capture_output=True,timeout=5)
   thread.join();listener.close();self.assertNotEqual(p.returncode,0)
if __name__=='__main__':unittest.main()
