import copy
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location('identity_install', pathlib.Path(__file__).with_name('nuc_identity_install.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class FakeHost:
    def __init__(self):
        self.users={'bo':1000};self.groups={'bo':1000};self.files={};self.failure=None
        self.orphans=set();self.paths={p:{'dev':1,'ino':i+1,'uid':0,'gid':0,'mode':0o755,'directory':True,'symlink':False} for i,p in enumerate(m.ANCESTORS)}
    def require_root(self): pass
    def machine(self): return 'fixture-machine'
    def script_digest(self): return 'fixture-source'
    def accounts(self): return self.users.copy(),self.groups.copy()
    def occupied_filesystem_ids(self): return self.orphans.copy(), {'fixture':'complete'}
    def identity(self,p): return copy.deepcopy(self.paths.get(p))
    def check_acl(self,p):
        if self.failure == ('acl',p): raise m.Refused('unsafe ACL')
    def db(self,name):
        if name=='passwd':
            return b'bo:x:1000:1000::/home/bo:/bin/sh\n'+b''.join(f'{r}:x:{uid}:{uid}::/nonexistent:/usr/sbin/nologin\n'.encode() for r,uid in self.users.items() if r!='bo')
        return b'bo:x:1000:\n'+b''.join(f'{r}:x:{gid}:\n'.encode() for r,gid in self.groups.items() if r!='bo')
    def secret_db(self,name):
        if name=='shadow':
            return b'bo:SYNTHETIC_SHADOW_SENTINEL:1:2:3:4:5:6:7\n'+b''.join(f'{r}:!:1:2:3:4:5:6:7\n'.encode() for r in self.users if r!='bo')
        if name=='gshadow':
            return b'bo:SYNTHETIC_GROUP_SENTINEL::\n'+b''.join(f'{r}:!::\n'.encode() for r in self.groups if r!='bo')
        raise m.Refused('invalid private database')
    def mkdir(self,p,mode):
        if p in self.paths: raise FileExistsError(p)
        self.paths[p]={'dev':1,'ino':len(self.paths)+1,'uid':0,'gid':0,'mode':mode,'directory':True,'symlink':False}
    def write(self,p,data):
        if p in self.files: raise FileExistsError(p)
        self.files[p]=data
    def chown(self,p,uid,gid):
        self.paths[p]['uid']=uid;self.paths[p]['gid']=gid
    def verify_user(self,r,uid,gid):
        if self.users.get(r)!=uid or self.groups.get(r)!=gid: raise m.Refused("bad account")
    def add_group(self,r,gid): self.groups[r]=gid
    def add_user(self,r,uid,gid):
        if self.failure == ('user',r): raise RuntimeError('injected failure')
        self.users[r]=uid

class Installation(unittest.TestCase):
    def test_plan_and_apply_preserve_existing_state(self):
        h=FakeHost();h.files['/unrelated/data']=b'original';p=m.make_plan(h)
        self.assertEqual([x['uid'] for x in p['identities']],[2000,2001,2002,2003,2004])
        m.apply(h,p)
        self.assertEqual(h.files['/unrelated/data'],b'original')
        self.assertEqual(h.users['bo'],1000)
        self.assertEqual(h.paths[m.STATE+'/journal']['uid'],2004)
        self.assertEqual(h.paths[m.STATE]['mode'],0o711)
        self.assertIn(m.STATE+'/complete.json',h.files)
        with self.assertRaises(m.Refused):m.make_plan(h)
    def test_collision_and_stale_plan_do_not_mutate(self):
        h=FakeHost();p=m.make_plan(h);h.users['stranger']=2000
        with self.assertRaises(m.Refused):m.apply(h,p)
        self.assertNotIn(m.STATE,h.paths)
        h=FakeHost();h.paths[m.TARGETS[0]]={'directory':False,'symlink':True,'uid':0,'mode':0}
        with self.assertRaises(m.Refused):m.make_plan(h)
        self.assertNotIn(m.STATE,h.paths)
    def test_unsafe_ancestors_and_acls_are_rejected(self):
        h=FakeHost();h.paths['/etc']['mode']=0o777
        with self.assertRaises(m.Refused):m.make_plan(h)
        h=FakeHost();h.failure=('acl','/var/lib')
        with self.assertRaises(m.Refused):m.make_plan(h)
    def test_partial_failure_is_retained_and_cannot_retry(self):
        h=FakeHost();p=m.make_plan(h);h.failure=('user','sfgoose-worker')
        with self.assertRaises(RuntimeError):m.apply(h,p)
        self.assertEqual(h.users['bo'],1000)
        self.assertNotIn('sfgoose-worker',h.users)
        self.assertIn('sfgoose-worker',h.groups)
        self.assertTrue(any(b'create locked user sfgoose-worker' in value for name,value in h.files.items() if name.endswith('-intent.json')))
        self.assertNotIn(m.STATE+'/complete.json',h.files)
        with self.assertRaises(m.Refused):m.make_plan(h)
    def test_orphan_owned_uid_is_not_selected(self):
        h=FakeHost();h.orphans={2000,2002};p=m.make_plan(h)
        self.assertEqual([x['uid'] for x in p['identities']],[2001,2003,2004,2005,2006])
    def test_other_account_record_mutation_is_detected(self):
        before=b'bo:x:1000:1000::/home/bo:/bin/sh\n'
        after=b'bo:x:1000:1000::/home/bo:/bin/false\nsfgoose-control:x:2000:2000::/nonexistent:/usr/sbin/nologin\n'
        with self.assertRaises(m.Refused):m.assert_existing_records_preserved(before,after,'sfgoose-control')
        good=before+b'sfgoose-control:x:2000:2000::/nonexistent:/usr/sbin/nologin\n'
        m.assert_existing_records_preserved(before,good,'sfgoose-control')

    def test_apply_detects_existing_record_corruption_before_done_receipt(self):
        class CorruptingHost(FakeHost):
            corrupt = False
            def add_user(self,r,uid,gid):
                super().add_user(r,uid,gid)
                self.corrupt = True
            def db(self,name):
                value = super().db(name)
                return value.replace(b'/bin/sh', b'/bin/false') if name == 'passwd' and self.corrupt else value
        h=CorruptingHost();p=m.make_plan(h)
        with self.assertRaises(m.Refused):m.apply(h,p)
        self.assertTrue(any(b'create locked user sfgoose-control' in v for k,v in h.files.items() if k.endswith('-intent.json')))
        self.assertFalse(any(b'create locked user sfgoose-control' in v for k,v in h.files.items() if k.endswith('-done.json')))
        self.assertNotIn(m.STATE+'/complete.json',h.files)

    def test_secret_database_preservation_and_no_leak(self):
        class SecretCorruptingHost(FakeHost):
            corrupt=False
            def add_user(self,r,uid,gid):
                super().add_user(r,uid,gid); self.corrupt=True
            def secret_db(self,name):
                value=super().secret_db(name)
                return value.replace(b'SYNTHETIC_SHADOW_SENTINEL',b'changed') if self.corrupt and name=='shadow' else value
        h=SecretCorruptingHost();p=m.make_plan(h)
        with self.assertRaises(m.Refused) as caught: m.apply(h,p)
        self.assertNotIn('SYNTHETIC_',str(caught.exception))
        self.assertFalse(any(b'SYNTHETIC_' in v for v in h.files.values()))
        self.assertNotIn(m.STATE+'/complete.json',h.files)
        h=FakeHost();p=m.make_plan(h);m.apply(h,p)
        self.assertFalse(any(b'SYNTHETIC_' in v for v in h.files.values()))
        self.assertNotIn('SYNTHETIC_',str(p))

    def test_gshadow_corruption_after_groupadd_fails_without_leak(self):
        class CorruptGroupHost(FakeHost):
            corrupt=False
            def add_group(self,r,gid):
                super().add_group(r,gid); self.corrupt=True
            def secret_db(self,name):
                value=super().secret_db(name)
                return value.replace(b'SYNTHETIC_GROUP_SENTINEL',b'changed') if self.corrupt and name=='gshadow' else value
        h=CorruptGroupHost();p=m.make_plan(h)
        with self.assertRaises(m.Refused) as caught:m.apply(h,p)
        self.assertNotIn('SYNTHETIC_',str(caught.exception))
        self.assertFalse(any(b'SYNTHETIC_' in v for v in h.files.values()))
        self.assertNotIn(m.STATE+'/complete.json',h.files)
        self.assertTrue(any(b'create group sfgoose-control' in v for k,v in h.files.items() if k.endswith('-intent.json')))
        self.assertFalse(any(b'create group sfgoose-control' in v for k,v in h.files.items() if k.endswith('-done.json')))

    def test_excluded_daemon_overlay_changes_do_not_change_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            base=pathlib.Path(root); (base/'docker').mkdir(); (base/'data').mkdir()
            (base/'data'/'persist').write_text('fixture')
            excluded={str(base/'docker')}
            first,scope1=m.scan_metadata([root],set(),excluded)
            (base/'docker'/'unique-bridge-overlay').mkdir()
            (base/'docker'/'unique-bridge-overlay'/'private').write_text('ignored')
            original_scandir=m.os.scandir
            def refuse_excluded(path):
                if str(path) in excluded: raise AssertionError('excluded daemon root scanned')
                return original_scandir(path)
            with mock.patch.object(m.os,'scandir',side_effect=refuse_excluded):
                second,scope2=m.scan_metadata([root],set(),excluded)
            self.assertEqual(first,second)
            self.assertEqual(scope1,scope2)
            self.assertEqual(scope1['roots'][0]['root'],root)

    def test_daemon_exclusions_require_verified_root_and_acl(self):
        class ProtectedHost(m.Host):
            def __init__(self): self.bad=False;self.bad_acl=False
            def identity(self,path):
                return {'dev':1,'ino':2 if path.endswith('docker') else 3,'uid':0,'gid':0,
                        'mode':0o777 if self.bad else 0o710,'directory':True,'symlink':False}
            def check_acl(self,path):
                if self.bad_acl:raise m.Refused('unsafe ACL')
        h=ProtectedHost()
        with mock.patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout='/var/lib/docker\n')):
            self.assertEqual(set(h.protected_daemon_dirs()),{'/var/lib/docker','/var/lib/containerd'})
            h.bad=True
            with self.assertRaises(m.Refused):h.protected_daemon_dirs()
            h.bad=False;h.bad_acl=True
            with self.assertRaises(m.Refused):h.protected_daemon_dirs()
        with mock.patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout='/unexpected\n')):
            with self.assertRaises(m.Refused):h.protected_daemon_dirs()

    def test_plan_is_bound_to_script_and_machine(self):
        h=FakeHost();p=m.make_plan(h);p['machine']='other'
        with self.assertRaises(m.Refused):m.apply(h,p)
        self.assertFalse(h.files)

if __name__=='__main__':unittest.main()
