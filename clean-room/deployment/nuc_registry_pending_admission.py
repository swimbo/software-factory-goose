"""Require an independently published prospective SDK5 admission before opening the gate.

Called only by the exclusive-lock holder while the transition marker remains.
The reviewed launcher pin remains unavailable until its package is frozen.
"""
import pathlib,subprocess
import nuc_sdk5_admission_receipt as contract

LAUNCHER=pathlib.Path('/usr/local/libexec/software-factory-goose/registry-v5-admission-producer-v2')
PACKAGE=pathlib.Path('/etc/software-factory-goose/registry-v5-admission-package-v2-complete.json')
RECEIPT=pathlib.Path('/etc/software-factory-goose/registry-v5-admission-complete.json')
# Filled only after the independently reviewed source package is frozen.
LAUNCHER_SHA256=None

def verify(gate,intent,replay,att,boot):
 gate.require(LAUNCHER_SHA256 is not None,'pending admission producer unavailable')
 package=gate._json(gate._protected_read(PACKAGE,0o600,16384))
 gate.require(type(package.get('schema')) is int and package=={'schema':1,'installed':True,'executed':False,'activated':False,'launcher_sha256':LAUNCHER_SHA256},'pending admission package unavailable')
 gate.require(gate._digest(gate._protected_read(LAUNCHER,0o755,1000000))==LAUNCHER_SHA256,'pending admission launcher changed')
 unix=gate._json(gate._protected_read(gate.ROOT/'history'/(intent['transition_id']+'.unix-restate-activation-complete.json'),0o600,16384));raw=gate._protected_read(RECEIPT,0o600,contract.MAX_BYTES)
 expected={'producer_sha256':LAUNCHER_SHA256,'boot_id':boot,'private_namespace_dev':att['netns_dev'],'private_namespace_ino':att['netns_ino'],'registry_sha256':intent['new_manifest_sha256'],'transition_id':intent['transition_id'],'deployment_id':replay['deployment_id'],'process_manifest_sha256':replay['attestation_sha256'],'admin_socket_dev':unix['socket_dev'],'admin_socket_ino':unix['socket_ino']}
 contract.validate(raw,expected)
 p=subprocess.run([str(LAUNCHER),'--verify-pending'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=175,check=False,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'})
 wanted={'schema':1,'admission_sha256':gate._digest(raw),'transition_id':intent['transition_id'],'manifest_sha256':intent['new_manifest_sha256'],'attestation_sha256':replay['attestation_sha256'],'boot_id':boot,'transition_still_closed':True}
 gate.require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'pending admission live proof unavailable')
 observed=gate._json(p.stdout);gate.require(isinstance(observed,dict) and type(observed.get('schema')) is int and observed==wanted and observed.get('transition_still_closed') is True,'pending admission live proof unavailable')
 gate.require(gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000))==intent,'transition marker changed')
