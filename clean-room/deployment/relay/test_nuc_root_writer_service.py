import io
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import nuc_root_writer_service as service
from nuc_relay_authority import Denied
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
class HostChecks(unittest.TestCase):
    def test_closed_or_frozen_blocks_provider_inspect(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp);state=path/'state';cg=path/'cg';state.mkdir();cg.mkdir()
            (cg/'cgroup.freeze').write_text('0\n');(cg/'cgroup.events').write_text('populated 1\nfrozen 0\n')
            state_fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY);cg_fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY)
            st=os.fstat(cg_fd)
            task={'boot_id':'boot','cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino}
            scope={'task_id':'task','grant_sha256':'a'*64,'catalog_sha256':'b'*64,'provider_binding_sha256':'c'*64}
            binding={'network_device':1,'network_inode':2}
            guard=service.HostAuthority(G,scope,binding,{},task,state_fd,cg_fd)
            original_stat=os.stat
            def fake_stat(path,*args,**kwargs):
                if path==service.CG+'/sfactory'+G.lower()+'.slice':return st
                return original_stat(path,*args,**kwargs)
            try:
                with patch('builtins.open',side_effect=lambda *a,**k:io.StringIO('boot\n')),patch.object(service.os,'stat',side_effect=fake_stat),patch.object(service,'read_deadline_file',return_value=b'{}'),patch.object(service,'verify_deadline_records'),patch.object(service,'inspect_bifrost') as inspect,patch.object(service,'inspect_writer',return_value=123),patch.object(service,'verify_process_protection'):
                    self.assertTrue(guard.verify()['open']);self.assertEqual(inspect.call_count,1)
                    (state/(G+'.closed')).write_text('anything')
                    with self.assertRaises(Denied):guard.verify()
                    self.assertEqual(inspect.call_count,1)
                    (state/(G+'.closed')).unlink();(cg/'cgroup.freeze').write_text('1\n')
                    with self.assertRaises(Denied):guard.verify()
                    self.assertEqual(inspect.call_count,1)
            finally:os.close(state_fd);os.close(cg_fd)

if __name__=='__main__':unittest.main()

class WriterInspect(unittest.TestCase):
    def test_fixed_writer_profile_and_mounts(self):
        import copy,hashlib,json
        paths={'candidate_dir':'/candidate-host','input_dir':'/input-host','output_dir':'/output-host'}
        normalized=[{'source':paths['candidate_dir'],'destination':'/candidate','rw':True},
                    {'source':paths['input_dir'],'destination':'/handoff/input','rw':False},
                    {'source':paths['output_dir'],'destination':'/handoff/output','rw':True}]
        binding={'generation':G,'writer_container_id':'a'*64,'writer_image_sha256':'b'*64,
                 'mounts_sha256':hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        binding.update({key:{'path':value} for key,value in paths.items()})
        obj={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'Status':'running'},
             'Config':{'User':'2001:2001','Entrypoint':['/usr/local/bin/python3','-I','-B','/factory/nuc_fixed_writer.py'],'Cmd':None},
             'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'RestartPolicy':{'Name':'no'},'SecurityOpt':['no-new-privileges:true']},
             'Mounts':[{'Type':'bind','Source':m['source'],'Destination':m['destination'],'RW':m['rw']} for m in normalized]}
        cgroup='0::/system.slice/sfactory'+G.lower()+'.slice/docker-abc.scope\n'
        with patch('builtins.open',side_effect=lambda *a,**k:io.StringIO(cgroup)):
            self.assertEqual(service.validate_writer_inspect(obj,binding),123)
            for key,value in [('Privileged',True),('NetworkMode','host'),('ReadonlyRootfs',False)]:
                bad=copy.deepcopy(obj);bad['HostConfig'][key]=value
                with self.assertRaises(Denied):service.validate_writer_inspect(bad,binding)
            bad=copy.deepcopy(obj);bad['Mounts'][1]['RW']=True
            with self.assertRaises(Denied):service.validate_writer_inspect(bad,binding)
        with patch('builtins.open',side_effect=lambda *a,**k:io.StringIO('0::/unrelated\n')):
            with self.assertRaises(Denied):service.validate_writer_inspect(obj,binding)

class RootProtocol(unittest.TestCase):
    def test_peer_and_fixed_operation(self):
        import json,socket,struct
        class Peer:
            def __init__(self,sock,uid):self.sock=sock;self.uid=uid
            def getsockopt(self,*_):return struct.pack('3i',9,self.uid,2000)
            def settimeout(self,value):self.sock.settimeout(value)
            def recv(self,n):return self.sock.recv(n)
            def sendall(self,data):self.sock.sendall(data)
        class Broker:
            def __init__(self):self.requests=[]
            def guard(self):self.requests.append('guard');return {'open':True}
            def write_files(self,value):self.requests.append(value);return {'status':'ok'}
        for uid,frame,accepted in [(2000,b'{"op":"guard"}\n',True),(2001,b'{"op":"guard"}\n',False),
                                   (2000,b'{"op":"write_files","files":{},"path":"/tmp"}\n',False)]:
            a,b=socket.socketpair();handler=Broker()
            try:
                b.sendall(frame)
                with patch.object(service.socket,'SO_PEERCRED',17,create=True):
                    if accepted:service.receive(Peer(a,uid),handler)
                    else:
                        with self.assertRaises(Denied):service.receive(Peer(a,uid),handler)
                self.assertEqual(bool(handler.requests),accepted)
                if accepted:self.assertEqual(json.loads(b.recv(1024))['open'],True)
            finally:a.close();b.close()

class DeadlineChecks(unittest.TestCase):
    def records(self):
        import hashlib,json
        scope={'task_id':'task','grant_sha256':'a'*64};task={'boot_id':'boot'}
        grant={'schema':1,'generation':G,'binding_sha256':'a'*64,'reservation':{'generation':G,'scope':{'generation':G,'task_id':'task'},'expires_at_ms':1000,'hard_deadline_ms':1200}}
        raw=json.dumps(grant,sort_keys=True).encode()
        armed={'schema':1,'target':G,'boot_id':'boot','binding_sha256':'a'*64,'verified_grant_sha256':hashlib.sha256(raw).hexdigest(),'wake_monotonic_ns':2000,'expiry_ms':1000,'engine_effects':False}
        return scope,task,armed,raw
    def test_live_and_expired_and_changed_binding(self):
        import json
        scope,task,armed,raw=self.records()
        service.verify_deadline_records(G,scope,task,json.dumps(armed).encode(),raw,999,1999)
        for changes,wall,mono in [({},1000,1999),({},999,2000),({'binding_sha256':'b'*64},999,1999),({'verified_grant_sha256':'c'*64},999,1999)]:
            with self.assertRaises(Denied):service.verify_deadline_records(G,scope,task,json.dumps({**armed,**changes}).encode(),raw,wall,mono)
    def test_expired_stops_before_provider_or_writer_inspection(self):
        import json,tempfile,pathlib,os
        scope,task,armed,raw=self.records()
        with tempfile.TemporaryDirectory() as tmp:
            fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            guard=service.HostAuthority(G,scope,{}, {},task,fd,fd)
            try:
                with patch.object(service,'read_deadline_file',side_effect=[json.dumps(armed).encode(),raw]),patch.object(service.time,'time_ns',return_value=1000*1_000_000),patch.object(service.time,'monotonic_ns',return_value=1999),patch.object(service,'inspect_bifrost') as provider,patch.object(service,'inspect_writer') as writer:
                    with self.assertRaises(Denied):guard.verify()
                    provider.assert_not_called();writer.assert_not_called()
            finally:os.close(fd)

class ActivatedListener(unittest.TestCase):
 def test_socket_fd_and_filesystem_inodes_are_independent(self):
  import errno,socket,stat,types
  class Listener:
   def getsockname(self):return '/run/software-factory-goose/writer/'+G+'.sock'
   def getsockopt(self,*args):return 1
   def close(self):pass
  endpoint=types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=2000,st_nlink=1,st_dev=25,st_ino=123)
  with patch.object(service.socket,'fromfd',return_value=Listener()),patch.object(service,'safe_dir',return_value=5),patch.object(service.os,'close'),patch.object(service.os,'stat',return_value=endpoint),patch.object(service.os,'getxattr',side_effect=OSError(errno.ENODATA,'none'),create=True):
   service.validate_writer_listener(3,G)
  with patch.object(service.socket,'fromfd',return_value=Listener()),patch.object(service,'safe_dir',return_value=5),patch.object(service.os,'close'),patch.object(service.os,'stat',return_value=endpoint),patch.object(service.os,'getxattr',return_value=b'acl',create=True):
   with self.assertRaises(Denied):service.validate_writer_listener(3,G)
