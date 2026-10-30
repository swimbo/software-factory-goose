import copy,hashlib,json,pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_registry_attestation_profiles as profiles

def fixture(profile):
    cfg={'sdk_port':profile['port'],'intent_id':profile['intent'],'task_id':profile['task'],'launch_scope':{'intent_id':profile['intent'],'task_id':profile['task'],'generation':profile['generation'],'catalog_sha256':'a'*64}}
    raw=json.dumps(cfg).encode();entry={'config':profile['config'],'config_sha256':hashlib.sha256(raw).hexdigest(),'evidence':'fixed-evidence.json','evidence_sha256':'b'*64,'catalog_sha256':'a'*64}
    manifest={'schema':1,'active_intent':profile['intent'],'entries':[entry]}
    return manifest,raw
class RegistryProfilesTests(unittest.TestCase):
    def test_sdk4_exact_pair(self):
        manifest,raw=fixture(profiles.SDK4);result=profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw)
        self.assertEqual(result['attestation'].name,'registry-process-attestation.json');self.assertEqual(result['probe'].name,'registry-attestor-probe')
    def test_sdk5_exact_pair(self):
        manifest,raw=fixture(profiles.SDK5)
        result=profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw)
        self.assertEqual(result['attestation'].name,'registry-v5-process-attestation.json');self.assertEqual(result['probe'].name,'registry-v5-attestor-probe')
    def test_cross_profile_config_and_tampering_refused(self):
        for source,target in ((profiles.SDK4,profiles.SDK5),(profiles.SDK5,profiles.SDK4)):
            manifest,raw=fixture(source);other,_=fixture(target);manifest['active_intent']=target['intent'];manifest['entries']=other['entries']
            with self.subTest(source=source['profile']),self.assertRaises(RuntimeError):profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw)
        manifest,raw=fixture(profiles.SDK4)
        with self.assertRaises(RuntimeError):profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw+b' ')
    def test_signed_config_cannot_swap_port_or_scope(self):
        for field in ('port','intent','task','generation','catalog'):
            manifest,raw=fixture(profiles.SDK4);cfg=json.loads(raw)
            if field=='port':cfg['sdk_port']=9085
            if field=='intent':cfg['launch_scope']['intent_id']=profiles.SDK5['intent']
            if field=='task':cfg['launch_scope']['task_id']=profiles.SDK5['task']
            if field=='generation':cfg['launch_scope']['generation']=profiles.SDK5['generation']
            if field=='catalog':cfg['launch_scope']['catalog_sha256']='c'*64
            raw=json.dumps(cfg).encode();manifest['entries'][0]['config_sha256']=hashlib.sha256(raw).hexdigest()
            with self.subTest(field=field),self.assertRaises(RuntimeError):profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw)

    def test_unknown_and_duplicate_fields_denied(self):
        manifest,raw=fixture(profiles.SDK4);manifest['active_intent']='unknown'
        with self.assertRaises(RuntimeError):profiles.select_for_registry(json.dumps(manifest).encode(),lambda _:raw)
        with self.assertRaises(RuntimeError):profiles.decode(b'{"schema":1,"schema":1}')

class RegistryHeadBindingTests(unittest.TestCase):
    def test_head_reads_attestation_from_selected_profile(self):
        import os,tempfile
        import nuc_registry_transition_gate as gate
        boot='98b86bb5-c04c-46f5-951d-22e497102f29';transition='01ARZ3NDEKTSV4RRFFQ69G5FAM'
        for selected in (profiles.SDK4,profiles.SDK5):
            manifest,config=fixture(selected);reg=json.dumps(manifest).encode();regsha=hashlib.sha256(reg).hexdigest()
            att=json.dumps({'boot_id':boot,'config_sha256':regsha}).encode();attsha=hashlib.sha256(att).hexdigest()
            intent=json.dumps({'transition_id':transition,'new_manifest_sha256':regsha}).encode();replay=b'fixture';complete=json.dumps({'schema':1,'transition_id':transition,'boot_id':boot,'manifest_sha256':regsha,'attestation_sha256':attsha,'replay_sha256':hashlib.sha256(replay).hexdigest(),'intent_sha256':hashlib.sha256(intent).hexdigest()}).encode();head=json.dumps({'schema':1,'transition_id':transition,'boot_id':boot,'manifest_sha256':regsha,'attestation_sha256':attsha,'completion_sha256':hashlib.sha256(complete).hexdigest()}).encode()
            files={gate.ROOT/'head.json':head,gate.ROOT/'history'/(transition+'.complete.json'):complete,gate.ROOT/'history'/(transition+'.intent.json'):intent,gate.ROOT/'history'/(transition+'.replay.json'):replay,gate.REGISTRY:reg,selected['attestation']:att,profiles.ETC/selected['config']:config,selected['probe']:b'fixture-probe'}
            def read(path,*args):
                if path not in files:raise FileNotFoundError(path)
                return files[path]
            with self.subTest(profile=selected['profile']),tempfile.TemporaryDirectory() as tmp,mock.patch.object(gate,'_directory',side_effect=lambda *_:os.open(tmp,os.O_RDONLY)),mock.patch.object(gate,'_protected_read',side_effect=read),mock.patch.object(pathlib.Path,'read_text',return_value=boot),mock.patch.dict(selected,{'probe_sha256':hashlib.sha256(b'fixture-probe').hexdigest()}):
                self.assertEqual(gate.verify_head()['manifest_sha256'],regsha)
                files.pop(selected['probe'])
                with self.assertRaises(FileNotFoundError):gate.verify_head()
                files[selected['probe']]=b'fixture-probe'
                files.pop(selected['attestation']);other=profiles.SDK5 if selected['profile']=='sdk4' else profiles.SDK4;files[other['attestation']]=att
                with self.assertRaises(FileNotFoundError):gate.verify_head()

if __name__=='__main__':unittest.main()
