"""Create-only relay package installation; no sockets, secret reads or dispatch."""
import hashlib,json,os,pathlib,stat
import nuc_worker_images_install as utility
SOURCE=pathlib.Path('/tmp/sfactory-relay-package-source')
DEST=pathlib.Path('/usr/local/libexec/software-factory-goose/relay')
MANIFEST=pathlib.Path('/etc/software-factory-goose/relay-package.json')
INTENT=pathlib.Path('/etc/software-factory-goose/relay-package-started.json')
PINS={'nuc_relay_authority.py': 'dc336c313e3dbdbee0a84e1adf764895a8487657129dd6ca7cbc562ae59e3032', 'nuc_relay_core.py': 'f49f23d99cb4f03fa4dd61af7f7eda8df35d7411cf1d6289715a52871cf513b4', 'nuc_relay_stream.py': '524bb2f1437af3251ffc1e8fbc5f9c8357eaa40bea242cde0086791d17701d55', 'nuc_relay_systemd.py': 'ea16c500e2f2f7786210801d22802be6e8736217e39933133da466e3a1312031', 'nuc_relay_provider.py': '7d8904f2fb88be13894497ccbca928f9e1acf7a3169ddfb49d231d4770bd5c7a', 'nuc_relay_server.py': 'af18c8022820f29b42fe7d3ca880f4a489de67ed866e3b8abaaeb1558ef47213', 'nuc_relay_guard.py': '9da14d3fd079203d5b78956955da973c82548e3cf29fd6409db4599f27711efe', 'nuc_relay_writer.py': '6c89cd37dd45c08b1ec9652c7bdca8fce3dc5cde57af95100a590d9fa431b5ea', 'nuc_root_writer_broker.py': 'f8620c398a1181b6ec8131e726b1c27bf6ef74e4b2ee0e89fc6228c1dd5bf759', 'nuc_root_writer_service.py': '4defa9d5566a8bcf987b17c9a5c910064a525b131618a4c37bdb26e9308eda39', 'nuc_writer_binding.py': '2f415a1eceb1627dd3ca8548d146f5c1ba0135c5564d14f497b2299a0204411e', 'nuc_root_deadline_arm.py': '195e385703e433eaafb2e30e36a4de08a3ef01f084b175f944b276643c1534f4', 'nuc_root_grant_deadline.py': 'd29a4ffab144ddc17afd4142d8cd965d1f325b61a6072895b49d40be66cc0fd7'}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 utility.directory(DEST.parent);utility.directory(MANIFEST.parent);utility.directory(SOURCE,1000,0o700)
 if any(os.path.lexists(p) for p in (DEST,MANIFEST,INTENT)):raise RuntimeError('relay package already attempted')
 for name,sha in PINS.items():utility.read_source(SOURCE/name,sha,1_000_000)
 return {'component':'relay-package','source_sha256':host.source_digest,'files':PINS,'activation':False,'provider_credential_access':False}

def apply(host,reviewed):
 if make_plan(host)!=reviewed:raise RuntimeError('reviewed relay package changed')
 utility.create(INTENT,json.dumps(reviewed,sort_keys=True).encode())
 os.mkdir(DEST,0o755);os.chmod(DEST,0o755);utility.sync(DEST.parent)
 for name,sha in PINS.items():utility.create(DEST/name,utility.read_source(SOURCE/name,sha,1_000_000),0o444)
 result={'schema':1,'files':PINS}
 utility.create(MANIFEST,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n')
 return {'manifest_sha256':hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n').hexdigest(),'activation':False}
