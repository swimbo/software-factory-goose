import hashlib
import datetime
import importlib.util
import json
import os
import pathlib
import signal
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location('nuc_relay_authority', HERE / 'nuc_relay_authority.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
G = '01ARZ3NDEKTSV4RRFFQ69G5FAV'

BINDING={'schema':1,'container_id':'c'*64,'image_id':'sha256:'+'d'*64,'pid':123,'network_device':1,'network_inode':2,'sandbox_key':'/var/run/docker/netns/'+'e'*12,'port':8080}
BINDING_RAW=json.dumps(BINDING).encode()

def digest_request(request):
    value=json.loads(request);value['messages'][1]['content']=value['messages'][1]['content'].split('\n<turn-context>')[0]
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def scope(request):
    return {'schema':2,'request_contract':'goose-turn-context-v1','generation':G,'task_id':'task','grant_sha256':'a'*64,'catalog_sha256':hashlib.sha256(b'catalog').hexdigest(),
            'request_sha256':digest_request(request),'allowed_models':['provider/model'],'provider_binding_sha256':hashlib.sha256(BINDING_RAW).hexdigest()}

def request():
    return json.dumps({'model':'gpt-4o-mini','messages':[{'role':'system','content':'fixed'},
        {'role':'user','content':'task\n<turn-context>\n<current-time>'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S +00:00')+'</current-time>\n<working-directory>/work/task</working-directory>\n</turn-context>'}],'tools':[r.WRITE_TOOL],'max_tokens':16384,
        'stream':True,'stream_options':{'include_usage':True}},separators=(',',':')).encode()

class RelayAuthority(unittest.TestCase):
    def test_scope_matches_root_consumed_record_and_rejects_substitution(self):
        body=request(); payload=scope(body)
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)
            (path/'scope').write_text(json.dumps(payload))
            (path/'consumed').write_text(G+'\n'+'a'*64+'\n')
            (path/'catalog').write_bytes(b'catalog')
            (path/'binding').write_bytes(BINDING_RAW)
            os.chmod(path/'scope',0o600);os.chmod(path/'consumed',0o600);os.chmod(path/'catalog',0o600);os.chmod(path/'binding',0o600)
            a=os.open(path/'scope',os.O_RDONLY);b=os.open(path/'consumed',os.O_RDONLY);c=os.open(path/'catalog',os.O_RDONLY);e=os.open(path/'binding',os.O_RDONLY)
            original=os.fstat
            def fake(fd):
                s=original(fd)
                return SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_gid=0,st_nlink=s.st_nlink,st_size=s.st_size)
            try:
                with patch.object(r.os,'fstat',side_effect=fake):
                    self.assertEqual(r.load_root_scope(a,b,c,e),(payload,BINDING))
                    (path/'consumed').write_text(G+'\n'+'c'*64+'\n')
                    with self.assertRaises(r.Denied):r.load_root_scope(a,b,c,e)
            finally:os.close(a);os.close(b);os.close(c);os.close(e)

    def test_request_hash_and_schema_are_both_required(self):
        raw=request();s=scope(raw)
        self.assertEqual(r.verify_request(s,raw)['model'],'gpt-4o-mini')
        changed=json.loads(raw);changed['max_tokens']=1
        bad=json.dumps(changed,separators=(',',':')).encode()
        with self.assertRaises(r.Denied):r.verify_request(s,bad)
        s['request_sha256']=digest_request(bad)
        with self.assertRaises(r.Denied):r.verify_request(s,bad)
        changed=json.loads(raw);changed['tools'][0]['function']['name']='unsafe'
        bad=json.dumps(changed,separators=(',',':')).encode();s['request_sha256']=digest_request(bad)
        with self.assertRaises(r.Denied):r.verify_request(s,bad)
        changed=json.loads(raw);changed['stream_options']['include_usage']=1
        bad=json.dumps(changed,separators=(',',':')).encode();s['request_sha256']=digest_request(bad)
        with self.assertRaises(r.Denied):r.verify_request(s,bad)

    def test_normalized_context_stays_exact_and_fresh(self):
        raw=request();s=scope(raw);value=json.loads(raw)
        old=value['messages'][1]['content']
        stamp=old.split('<current-time>')[1].split('</current-time>')[0]
        issued=datetime.datetime.strptime(stamp,'%Y-%m-%d %H:%M:%S %z').timestamp()
        with patch.object(r.time,'time',return_value=issued+119):self.assertEqual(r.verify_request(s,raw)['model'],'gpt-4o-mini')
        with patch.object(r.time,'time',return_value=issued+121):
            with self.assertRaises(r.Denied):r.verify_request(s,raw)
        with patch.object(r.time,'time',return_value=issued-121):
            with self.assertRaises(r.Denied):r.verify_request(s,raw)
        cases=[old.replace('/work/task','/work/other'),
               old.replace('task\n<turn-context>','task\n<turn-context>spoof\n<turn-context>'),
               old.replace('task\n<turn-context>','changed\n<turn-context>'),
               old.replace(' +00:00',' +05:00'),
               old.replace(stamp,'2000-01-01 00:00:00 +00:00')]
        for content in cases:
            candidate=json.loads(raw);candidate['messages'][1]['content']=content
            with self.assertRaises(r.Denied):r.verify_request(s,json.dumps(candidate).encode())
        extra=json.loads(raw);extra['extra']='x'
        with self.assertRaises(r.Denied):r.verify_request(s,json.dumps(extra).encode())

    def test_root_fd_metadata_requires_read_only_single_link(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'file';path.write_bytes(b'x');os.chmod(path,0o600)
            fd=os.open(path,os.O_RDWR);original=os.fstat
            def fake(fd):
                s=original(fd);return SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_gid=0,st_nlink=1,st_size=s.st_size)
            try:
                with patch.object(r.os,'fstat',side_effect=fake):
                    with self.assertRaises(r.Denied):r._root_bytes(fd,10)
            finally:os.close(fd)

    def test_fixed_writer_only(self):
        good=b'{"files":{"hello.py":"print(1)","test_hello.py":"pass"}}'
        self.assertEqual(set(r.validate_writer_arguments(good)['files']), {'hello.py', 'test_hello.py'})
        for raw in [b'{"files":{"../hello.py":"x","test_hello.py":"y"}}',
                    b'{"files":{"hello.py":"x","hello.py":"y","test_hello.py":"z"}}',
                    b'{"files":{"hello.py":"x","test_hello.py":"y"},"command":"id"}',
                    b'{"files":{"hello.py":"\\u0000","test_hello.py":"y"}}']:
            with self.assertRaises(r.Denied):r.validate_writer_arguments(raw)

    def test_linux_kernel_peer_cannot_be_selected_by_request(self):
        class Conn:
            def __init__(self, uid):self.uid=uid
            def getsockopt(self, *_):return r.struct.pack('3i', 123, self.uid, 2001)
        with patch.object(r.os, 'getuid', return_value=2000), patch.object(r.socket, 'SO_PEERCRED', 17, create=True):
            r.require_worker_peer(Conn(2001))
            with self.assertRaises(r.Denied):r.require_worker_peer(Conn(2000))
        with patch.object(r.os, 'getuid', return_value=1000), patch.object(r.socket, 'SO_PEERCRED', 17, create=True):
            with self.assertRaises(r.Denied):r.require_worker_peer(Conn(2001))

    def test_one_shot_fence_survives_object_restart_and_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
            original=os.fstat
            def fake(fd):
                s=original(fd)
                if stat.S_ISDIR(s.st_mode):return SimpleNamespace(st_mode=s.st_mode,st_uid=2000,st_gid=2000)
                return s
            try:
                with patch.object(r.os,'fstat',side_effect=fake):
                    first=r.EffectFence(fd);first.begin(G,'inference0','d'*64)
                    second=r.EffectFence(fd)
                    with self.assertRaises(r.Denied):second.begin(G,'inference0','d'*64)
                    with self.assertRaises(r.Denied):second.begin(G,'inference0','e'*64)
                    os.close(first.dirfd);os.close(second.dirfd)
            finally:os.close(fd)

    def test_concurrent_effect_intents_have_one_winner(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
            original=os.fstat
            def fake(fd):
                s=original(fd)
                if stat.S_ISDIR(s.st_mode):return SimpleNamespace(st_mode=s.st_mode,st_uid=2000,st_gid=2000)
                return s
            try:
                with patch.object(r.os,'fstat',side_effect=fake):
                    fence=r.EffectFence(fd)
                    def begin(_):
                        try:fence.begin(G,'inference0','d'*64);return True
                        except r.Denied:return False
                    with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(begin,range(16)))
                    self.assertEqual(sum(results),1)
                    os.close(fence.dirfd)
            finally:os.close(fd)

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX process')
    def test_fsynced_marker_survives_owner_sigkill(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
            original=os.fstat
            def fake(fd):
                s=original(fd)
                if stat.S_ISDIR(s.st_mode):return SimpleNamespace(st_mode=s.st_mode,st_uid=2000,st_gid=2000)
                return s
            try:
                with patch.object(r.os,'fstat',side_effect=fake):
                    pid=os.fork()
                    if pid==0:
                        try:
                            fence=r.EffectFence(fd);fence.begin(G,'writer','f'*64)
                            os.kill(os.getpid(),signal.SIGKILL)
                        finally:os._exit(99)
                    _,status=os.waitpid(pid,0)
                    self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                    reopened=r.EffectFence(fd)
                    try:
                        with self.assertRaises(r.Denied):reopened.begin(G,'writer','f'*64)
                    finally:os.close(reopened.dirfd)
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
