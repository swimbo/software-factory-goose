"""Create-only fixed v5 admission producer package; never execute it."""
import hashlib,json,os
import nuc_grant_sidecar_install as old
PINS = {'nuc_grant_admin_inspection.py': '6e43e77b6f1c7231c60fc96b6795a3ddfd6380bda71d305ade135df49b24e617',
 'nuc_grant_failed_inventory.py': '0de922f0d3ad93d40e7e3c289b959449746a96c0b0afc9586e3a3fc8e6d2dfda',
 'nuc_grant_sidecar_install.py': 'c8d3ebb2ba4707fdb2600564a1ef3bbc558e7c433cc09413df51e4d8bf87f3b6',
 'nuc_grant_sidecar_resume.py': 'a40b320a0f95ccfc421ec4d14380ce8d4cb969e3952779c6a0962965738f366b',
 'nuc_private_runtime_install.py': '63e89db3efd005064543d37f4fe5a819f82e95adbb5fe90c5e5f9fcacdef28b6',
 'nuc_real_catalog.py': '15e1b3a6111f6381c3153b9e671755728269e2e0f35150eae62e262558c9e56d',
 'nuc_real_repo_install.py': 'e246ca3e37b1cf12062adb8d6bbf10b3964d83b23fa8f50605c6f86d1aafc020',
 'nuc_real_sidecar_activate.py': '651b44817e73a1ec4a49c4ecf24258e679763bc56fadc75bc9c4891527df7c31',
 'nuc_real_sidecar_install.py': 'bfd7dd29769588bfa010c3b1e5381a01dd5ff550b7fe1323b51acd5db412e0b4',
 'nuc_registry_admission_observe.py': 'e71fa1ea7e8d0303c8f0dc9f257d2b3a2448b0ccef6e0839854886fcf76d5025',
 'nuc_registry_attestation_profiles.py': '8a5c16086baf538c6d8000f979304f2059467844a1048a3c0cd811c942f7e50a',
 'nuc_registry_external_preservation.py': '81ac913cb16a9080a17e732da910e31160297432a7747c4ef0d7f72f8a12551c',
 'nuc_registry_process_attestation.py': '7dc4936fdc26486826d5dff39048dd7f8bab09a4f1fa8ded7c0964af3243aa71',
 'nuc_registry_retirement_coordinator.py': 'b176de7c7a0859e786f018a99d654120b6df23019098ea534e97df8defd15944',
 'nuc_registry_sidecar_activate.py': '9c3bea05fef75f01a23f9a31a5a22901066e35b9bd9cedd51da0646665b45bb1',
 'nuc_registry_sidecar_install.py': '3f539fe4a723a58f1693fee737aea1b065c69eebcfb0104b171e1c600da0bc9e',
 'nuc_registry_transition_gate.py': '8928d88597ce92132d7c81e4e097a14b2b82cccfdae3b9b7006b991f3b27c0d7',
 'nuc_registry_v5_admission_producer.py': '94ef74223fbbde474ef0f6391725660905965432ec38fce3f933e95a4be23877',
 'nuc_registry_v5_install.py': 'f80148d6f88a9fa30e1cc599c32970cca3a5a24ccdccb5b88861c4068cc94a6e',
 'nuc_registry_v5_manifest_candidate.py': '9f1d98512bb0e7753773c8572a8a11c09325e6e84f9825da6ebbc13484dd4ee1',
 'nuc_sdk5_admission_receipt.py': '3d547e70e71555c17680a99c3f246a4afd0f54c259511588ab9ba8c059c88362'}
LAUNCHER = b"#!/usr/bin/python3 -I\nimport errno,hashlib,os,pathlib,runpy,stat,sys\nROOT=pathlib.Path('/usr/local/libexec/software-factory-goose/registry-v5-admission-code')\nPINS={'nuc_grant_admin_inspection.py': '6e43e77b6f1c7231c60fc96b6795a3ddfd6380bda71d305ade135df49b24e617', 'nuc_grant_failed_inventory.py': '0de922f0d3ad93d40e7e3c289b959449746a96c0b0afc9586e3a3fc8e6d2dfda', 'nuc_grant_sidecar_install.py': 'c8d3ebb2ba4707fdb2600564a1ef3bbc558e7c433cc09413df51e4d8bf87f3b6', 'nuc_grant_sidecar_resume.py': 'a40b320a0f95ccfc421ec4d14380ce8d4cb969e3952779c6a0962965738f366b', 'nuc_private_runtime_install.py': '63e89db3efd005064543d37f4fe5a819f82e95adbb5fe90c5e5f9fcacdef28b6', 'nuc_real_catalog.py': '15e1b3a6111f6381c3153b9e671755728269e2e0f35150eae62e262558c9e56d', 'nuc_real_repo_install.py': 'e246ca3e37b1cf12062adb8d6bbf10b3964d83b23fa8f50605c6f86d1aafc020', 'nuc_real_sidecar_activate.py': '651b44817e73a1ec4a49c4ecf24258e679763bc56fadc75bc9c4891527df7c31', 'nuc_real_sidecar_install.py': 'bfd7dd29769588bfa010c3b1e5381a01dd5ff550b7fe1323b51acd5db412e0b4', 'nuc_registry_admission_observe.py': 'e71fa1ea7e8d0303c8f0dc9f257d2b3a2448b0ccef6e0839854886fcf76d5025', 'nuc_registry_attestation_profiles.py': '8a5c16086baf538c6d8000f979304f2059467844a1048a3c0cd811c942f7e50a', 'nuc_registry_external_preservation.py': '81ac913cb16a9080a17e732da910e31160297432a7747c4ef0d7f72f8a12551c', 'nuc_registry_process_attestation.py': '7dc4936fdc26486826d5dff39048dd7f8bab09a4f1fa8ded7c0964af3243aa71', 'nuc_registry_retirement_coordinator.py': 'b176de7c7a0859e786f018a99d654120b6df23019098ea534e97df8defd15944', 'nuc_registry_sidecar_activate.py': '9c3bea05fef75f01a23f9a31a5a22901066e35b9bd9cedd51da0646665b45bb1', 'nuc_registry_sidecar_install.py': '3f539fe4a723a58f1693fee737aea1b065c69eebcfb0104b171e1c600da0bc9e', 'nuc_registry_transition_gate.py': '8928d88597ce92132d7c81e4e097a14b2b82cccfdae3b9b7006b991f3b27c0d7', 'nuc_registry_v5_admission_producer.py': '94ef74223fbbde474ef0f6391725660905965432ec38fce3f933e95a4be23877', 'nuc_registry_v5_install.py': 'f80148d6f88a9fa30e1cc599c32970cca3a5a24ccdccb5b88861c4068cc94a6e', 'nuc_registry_v5_manifest_candidate.py': '9f1d98512bb0e7753773c8572a8a11c09325e6e84f9825da6ebbc13484dd4ee1', 'nuc_sdk5_admission_receipt.py': '3d547e70e71555c17680a99c3f246a4afd0f54c259511588ab9ba8c059c88362'}\ndef fail():raise RuntimeError('admission package unavailable')\nfor path in [pathlib.Path('/'),*list(reversed(ROOT.parents[:-1])),ROOT]:\n fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  st=os.fstat(fd)\n  if st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022:fail()\n  for key in ('system.posix_acl_access','system.posix_acl_default'):\n   try:os.getxattr(fd,key)\n   except OSError as e:\n    if e.errno!=errno.ENODATA:fail()\n   else:fail()\n finally:os.close(fd)\nif set(os.listdir(ROOT))!=set(PINS):fail()\nfor name,digest in PINS.items():\n fd=os.open(ROOT/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)\n try:\n  a=os.fstat(fd)\n  if not stat.S_ISREG(a.st_mode) or (a.st_uid,a.st_gid,a.st_nlink,stat.S_IMODE(a.st_mode))!=(0,0,1,0o644) or a.st_size>1000000:fail()\n  try:os.getxattr(fd,'system.posix_acl_access')\n  except OSError as e:\n   if e.errno!=errno.ENODATA:fail()\n  else:fail()\n  h=hashlib.sha256();n=0\n  while b:=os.read(fd,65536):h.update(b);n+=len(b)\n  z=os.fstat(fd)\n  if n!=a.st_size or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) or h.hexdigest()!=digest:fail()\n finally:os.close(fd)\nsys.dont_write_bytecode=True\nsys.path.insert(0,str(ROOT))\nrunpy.run_module('nuc_registry_v5_admission_producer',run_name='__main__')\n"
SOURCES=None
ROOT=old.PREFIX/'registry-v5-admission-code';TARGET=old.PREFIX/'registry-v5-admission-producer'
START=old.ETC/'registry-v5-admission-package-started.json';DONE=old.ETC/'registry-v5-admission-package-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def plan():
 require(os.geteuid()==0 and isinstance(SOURCES,dict) and set(SOURCES)==set(PINS),'source bundle unavailable')
 for n,d in PINS.items():require(isinstance(SOURCES[n],bytes) and 0<len(SOURCES[n])<=1000000 and hashlib.sha256(SOURCES[n]).hexdigest()==d,'source changed')
 old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711);require(not any(os.path.lexists(p) for p in (ROOT,TARGET,START,DONE)),'package occupied')
 return {'schema':1,'sources':PINS,'bytes':sum(map(len,SOURCES.values())),'launcher_sha256':hashlib.sha256(LAUNCHER).hexdigest(),'scope':'create-only admission producer code; no execution or activation'}
def apply(reviewed):
 require(plan()==reviewed,'package plan changed');old.store(START,canonical(reviewed),0o600)
 os.mkdir(ROOT,0o755);os.chmod(ROOT,0o755);old.syncdir(ROOT.parent);old.directory(ROOT,0,0,0o755)
 for name in sorted(PINS):old.store(ROOT/name,SOURCES[name],0o644);old.read(ROOT/name,0o644,PINS[name],1000000)
 old.store(TARGET,LAUNCHER,0o755);old.read(TARGET,0o755,reviewed['launcher_sha256'],1000000)
 result={'schema':1,'installed':True,'executed':False,'activated':False,'launcher_sha256':reviewed['launcher_sha256']};old.store(DONE,canonical(result),0o600);return result
