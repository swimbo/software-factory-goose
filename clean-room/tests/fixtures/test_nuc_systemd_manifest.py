#!/usr/bin/env python3
"""Falsify cleanup against tampered manifests without Docker mutations."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from nuc_systemd_docker_recovery_spike import CLEANUP, SERVICE

class ManifestTests(unittest.TestCase):
    def run_case(self, edit, no_manifest=False, intent_edit=None, no_intent=False):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp); cgroup=root/'test-cgroup'; cgroup.mkdir()
            token='a'*32; label='org.software-factory.escape-spike'; slice_name='sfactory'+'b'*32+'-worker.slice'
            manifest={'id':'c'*64,'token':token,'label':label,'slice':slice_name,'inode':cgroup.stat().st_ino}
            intent={key:manifest[key] for key in ('token','label','slice','inode')}
            if intent_edit: intent.update(intent_edit)
            if not no_intent:
                ipath=root/'intent.json'; ipath.write_text(json.dumps(intent)); ipath.chmod(0o600)
            manifest.update(edit)
            if not no_manifest:
                path=root/'manifest.json'; path.write_text(json.dumps(manifest)); path.chmod(0o600)
            # Only inspect is permissible. Any cleanup call leaves an observable sentinel.
            (root/'docker_owner_guardian.py').write_text("LABEL="+repr(label)+"\ndef docker(*args): raise RuntimeError('unexpected engine call')\nclass DisposableContainer:\n def __init__(self,token): self.ident=None; self.name='sf-owner-'+token\n def inspect(self,target): raise RuntimeError('injected ID/label mismatch')\n def cleanup(self): open("+repr(str(root/'MUTATED'))+",'w').write('bad')\n")
            code=CLEANUP.replace("path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/intent['slice']",'path=pathlib.Path('+repr(str(cgroup))+')')
            (root/'cleanup.py').write_text(code)
            env=os.environ.copy(); env['SFACTORY_CGROUP_PARENT']=slice_name
            result=subprocess.run([sys.executable,str(root/'cleanup.py'),str(root),token],env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((root/'MUTATED').exists())
            self.assertTrue((root/'cleanup-result').read_text().startswith('ERROR '))
    def test_manifest_fsync_precedes_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp); cgroup=root/'test-cgroup'; cgroup.mkdir(); trace=root/'trace'
            label='org.software-factory.escape-spike'; token='a'*32
            (root/'docker_owner_guardian.py').write_text("LABEL="+repr(label)+"\nclass DisposableContainer:\n def __init__(self,token): pass\n def prepare(self): open("+repr(str(trace))+",'a').write('PREPARE\\n'); return 'c'*64\n def launch_prepared(self):\n  assert __import__('os').path.isfile("+repr(str(root/'manifest.json'))+")\n  open("+repr(str(trace))+",'a').write('LAUNCH\\n')\n")
            header="import os\n_real_fsync=os.fsync\ndef checked_fsync(fd):\n open("+repr(str(trace))+",'a').write('FSYNC\\n')\n return _real_fsync(fd)\nos.fsync=checked_fsync\n"
            code=SERVICE.replace("slice_path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/os.environ['SFACTORY_CGROUP_PARENT']",'slice_path=pathlib.Path('+repr(str(cgroup))+')').replace('time.sleep(25)','pass')
            (root/'service.py').write_text(header+code); (root/'launch').write_text('go')
            env=os.environ.copy(); env['SFACTORY_CGROUP_PARENT']='task-worker.slice'
            result=subprocess.run([sys.executable,str(root/'service.py'),str(root),token],env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(trace.read_text().splitlines(),['FSYNC','FSYNC','PREPARE','FSYNC','FSYNC','LAUNCH'])
            self.assertEqual(json.loads((root/'manifest.json').read_text())['token'],token)

    def test_missing_and_tampered_manifest_deny_mutation(self):
        for edit, missing in [({},True),({'token':'d'*32},False),({'label':'wrong'},False),({'id':'not-a-valid-full-id'},False),({'slice':'wrong'},False)]:
            with self.subTest(edit=edit,missing=missing): self.run_case(edit,no_manifest=missing)
    def test_missing_or_tampered_intent_denies_mutation(self):
        self.run_case({},no_intent=True)
        for edit in ({'token':'d'*32},{'label':'wrong'},{'slice':'wrong'},{'inode':-1}):
            with self.subTest(edit=edit): self.run_case({},intent_edit=edit)

    def test_precommit_running_or_ambiguous_target_is_quarantined(self):
        for case in ('missing','running','exited','wrong_slice','duplicate','bad_id'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root=pathlib.Path(temp); cg=root/'cg'; cg.mkdir(); token='a'*32; label='org.software-factory.escape-spike'; sl='sfactory'+'b'*32+'-worker.slice'; ident='c'*64
                intent={'token':token,'label':label,'slice':sl,'inode':cg.stat().st_ino}
                ip=root/'intent.json'; ip.write_text(json.dumps(intent)); ip.chmod(0o600)
                obj={'Id':ident,'Name':'/sf-owner-'+token,'HostConfig':{'CgroupParent':sl},'State':{'Running':False,'Status':'created'}}
                if case=='missing': obj=None
                if case=='running': obj['State']['Running']=True
                if case=='exited': obj['State']['Status']='exited'
                if case=='wrong_slice': obj['HostConfig']['CgroupParent']='wrong'
                if case=='bad_id': obj['Id']='bad'
                ids=ident+'\n'+('d'*64+'\n' if case=='duplicate' else '')
                fake="LABEL="+repr(label)+"\nclass Result: stdout="+repr(ids)+"\ndef docker(*args): return Result()\nclass DisposableContainer:\n def __init__(self,token): self.name='sf-owner-'+token; self.ident=None\n def inspect(self,target): return "+repr(obj)+"\n def cleanup(self): open("+repr(str(root/'MUTATED'))+",'w').write('bad')\n"
                (root/'docker_owner_guardian.py').write_text(fake)
                code=CLEANUP.replace("path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/intent['slice']",'path=pathlib.Path('+repr(str(cg))+')')
                (root/'cleanup.py').write_text(code)
                env=os.environ.copy(); env['SFACTORY_CGROUP_PARENT']=sl
                result=subprocess.run([sys.executable,str(root/'cleanup.py'),str(root),token],env=env,capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertFalse((root/'MUTATED').exists())
                self.assertTrue((root/'cleanup-result').read_text().startswith('ERROR '))

    def test_precommit_concurrent_start_is_never_signalled(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp); cg=root/'cg'; cg.mkdir(); token='a'*32; label='org.software-factory.escape-spike'; sl='sfactory'+'b'*32+'-worker.slice'; ident='c'*64
            intent={'token':token,'label':label,'slice':sl,'inode':cg.stat().st_ino}
            ip=root/'intent.json'; ip.write_text(json.dumps(intent)); ip.chmod(0o600)
            obj={'Id':ident,'Name':'/sf-owner-'+token,'HostConfig':{'CgroupParent':sl},'State':{'Running':False,'Status':'created'}}
            trace=root/'calls'
            fake="LABEL="+repr(label)+"\nclass Result: stdout="+repr(ident+'\n')+"\ndef docker(*args):\n open("+repr(str(trace))+",'a').write(args[0]+'\\n')\n if args[0]=='rm': raise RuntimeError('container started concurrently')\n return Result()\nclass DisposableContainer:\n def __init__(self,token): self.name='sf-owner-'+token; self.ident=None\n def inspect(self,target): return "+repr(obj)+"\n def cleanup(self): open("+repr(str(trace))+",'a').write('kill\\n')\n"
            (root/'docker_owner_guardian.py').write_text(fake)
            code=CLEANUP.replace("path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/intent['slice']",'path=pathlib.Path('+repr(str(cg))+')')
            (root/'cleanup.py').write_text(code)
            env=os.environ.copy(); env['SFACTORY_CGROUP_PARENT']=sl
            result=subprocess.run([sys.executable,str(root/'cleanup.py'),str(root),token],env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(trace.read_text().splitlines(),['ps','rm'])
            self.assertTrue((root/'cleanup-result').read_text().startswith('ERROR '))

    def test_valid_format_wrong_engine_identity_denies_mutation(self):
        self.run_case({'id':'e'*64})

if __name__=='__main__': unittest.main()
