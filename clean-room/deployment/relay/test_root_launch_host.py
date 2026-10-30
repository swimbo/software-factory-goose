import importlib.util,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('root_launch_host',Path(__file__).with_name('root-launch-host.py'));h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
G='01M65N5TM28WPH7BKQ153SPNJR';B='b'*64;W='a'*64;GID='c'*64
class HostTests(unittest.TestCase):
 def test_expired_deadline_denies_before_manager_or_effect(self):
  armed={'target':G,'engine_effects':False,'boot_id':'boot','expiry_ms':0,'wake_monotonic_ns':0}
  with patch.object(h.os.path,'lexists',return_value=False),patch.object(h,'load',return_value=armed),patch.object(h.pathlib.Path,'read_text',return_value='boot\n'),patch.object(h,'fixed_run') as manager:
   with self.assertRaises(RuntimeError):h.guard(G)
   manager.assert_not_called()
 def test_deadline_crossing_during_manager_check_denies(self):
  with tempfile.TemporaryDirectory() as temp:
   cg=Path(temp)/('sfactory'+G.lower()+'.slice');cg.mkdir();(cg/'cgroup.freeze').write_text('0\n');(cg/'cgroup.events').write_text('frozen 0\n');st=cg.stat()
   armed={'target':G,'engine_effects':False,'boot_id':'boot','expiry_ms':9999999999999,'wake_monotonic_ns':2000000000}
   stop={'target_id':G,'generation':G,'boot_id':'boot','cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino}
   def read(path):return armed if path.name.endswith('.deadline-armed.json') else stop
   def command(argv,**kwargs):return b'active\n' if argv[0].endswith('systemctl') else b't 2000000\n'
   with patch.object(h,'CGROUP',Path(temp)),patch.object(h.os.path,'lexists',return_value=False),patch.object(h,'load',side_effect=read),patch.object(h.pathlib.Path,'read_text',return_value='boot\n'),patch.object(h,'fixed_run',side_effect=command),patch.object(h.time,'monotonic_ns',side_effect=[1000000000,3000000000]):
    with self.assertRaises(RuntimeError):h.guard(G)
 def test_fixed_runner_times_out_owned_child(self):
  start=time.monotonic()
  with self.assertRaises(RuntimeError):h.fixed_run(['/bin/sleep','2'],timeout=.05)
  self.assertLess(time.monotonic()-start,1)
 def test_root_package_rejects_unpinned_module_before_exec(self):
  data=b'VALUE=1\n';manifest={'schema':1,'files':{'nuc_root_deadline_arm.py':h.digest(data),'nuc_root_grant_deadline.py':h.digest(data)}}
  with patch.object(h,'directory'),patch.object(h,'load',return_value=manifest),patch.object(h,'rootfile',return_value=data):
   a,b=h.modules();self.assertEqual((a.VALUE,b.VALUE),(1,1))
   manifest['files']['nuc_root_deadline_arm.py']='0'*64
   with self.assertRaises(RuntimeError):h.modules()
 def test_units_deny_stale_manager_or_prestarted_relay(self):
  names=h.unit_names(G);contents=b'fixed root unit';manifest={'schema':1,'generation':G,'units':{n:h.digest(contents) for n in names}}
  mutation={'stale':False,'relay_active':False}
  def prop(unit,key):
   base={'LoadState':'loaded','Names':unit,'FragmentPath':str(h.SYSTEM/unit),'DropInPaths':'','NeedDaemonReload':'yes' if mutation['stale'] else 'no','Job':'','Slice':'system.slice' if unit==names[1] else 'sfactory'+G.lower()+'.slice','NoNewPrivileges':'yes','CapabilityBoundingSet':'','ExecStartPre':'','ExecStartPost':'','Environment':'','EnvironmentFiles':'','Restart':'no','SocketUser':'root','SocketMode':'0660'}
   if key=='ActiveState':return 'active' if unit==names[2] or (unit==names[3] and mutation['relay_active']) else 'inactive'
   if key=='User':return 'root' if unit==names[1] else 'sfgoose-control'
   if key=='Group':return 'root' if unit==names[1] else 'sfgoose-control'
   if key=='ExecStart':return '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(h.PKG/('nuc_root_writer_service.py' if unit==names[1] else 'nuc_relay_server.py'))+(' '+G if unit==names[1] else '')+' ; ignore_errors=no ; }'
   if key=='SocketGroup':return 'sfgoose-control' if unit==names[0] else 'sfgoose-worker'
   if key=='FileDescriptorName':return 'writer' if unit==names[0] else 'callback'
   if key=='Listen':return str(h.RUN/'writer'/(G+'.sock'))+' (Stream)' if unit==names[0] else str(h.RUN/'relay'/G/'relay.sock')+' (Stream)'
   return base[key]
  with patch.object(h,'load',return_value=manifest),patch.object(h,'directory'),patch.object(h,'rootfile',return_value=contents),patch.object(h,'property_value',side_effect=prop):
   self.assertEqual(h.validate_units(G),names)
   mutation['stale']=True
   with self.assertRaises(RuntimeError):h.validate_units(G)
   mutation['stale']=False;mutation['relay_active']=True
   with self.assertRaises(RuntimeError):h.validate_units(G)
 def test_template_allows_only_exact_deepseek_routes(self):
  template={'schema':2,'request_contract':'goose-turn-context-v1','generation':G,'task_id':'task','request_sha256':'a'*64,'allowed_models':['deepseek-v4-pro:0813','deepseek-v4.1-flash:1017','ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017'],'provider_binding_sha256':'b'*64}
  raw=h.canonical(template);recipe={'relay_scope_template_sha256':h.digest(raw),'provider_binding_sha256':'b'*64};cat={'scope':{'task_id':'task'}}
  self.assertEqual(h.validate_template(G,cat,recipe,raw),template)
  template['allowed_models']=['gpt-4o-mini'];raw=h.canonical(template);recipe['relay_scope_template_sha256']=h.digest(raw)
  with self.assertRaises(RuntimeError):h.validate_template(G,cat,recipe,raw)
 def test_fixed_argv_has_no_dynamic_command_or_extra_mounts(self):
  w=h.docker_args(G,'writer');g=h.docker_args(G,'goose')
  self.assertEqual(w[-1],h.WRITER);self.assertEqual(g[-1],h.WORKER)
  self.assertEqual(w.count('--mount'),3);self.assertEqual(g.count('--mount'),4)
  self.assertNotIn('--entrypoint',w);self.assertNotIn('--entrypoint',g)
  self.assertIn('--tmpfs',g);self.assertNotIn('--tmpfs',w)
  self.assertIn('none',g);self.assertIn('2001:2001',w)
 def test_closure_after_create_retains_returned_id(self):
  writes=[]
  with patch.object(h,'guard',side_effect=[None,None,RuntimeError('closed')]),patch.object(h,'engine_guard'),patch.object(h,'store',side_effect=lambda p,b:writes.append((p.name,json.loads(b)))),patch.object(h,'fixed_run',return_value=(W+'\n').encode()),patch.object(h,'inspect') as inspect:
   with self.assertRaises(RuntimeError):h.create_role(G,'writer',B)
   inspect.assert_not_called()
  self.assertEqual([x[0] for x in writes],[G+'.writer-create-intent.json',G+'.writer-created.json'])
  self.assertEqual(writes[-1][1]['id'],W)
 def test_outer_reverification_allows_running_stage_only_after_writer_intent(self):
  with patch.object(h,'context',return_value=({}, {}, {}, B)),patch.object(h,'provenance'),patch.object(h,'validate_inputs'),patch.object(h,'validate_units') as units,patch.object(h.os.path,'lexists',side_effect=[False,False]):
   self.assertEqual(h.phase_verify(G,None),{'binding_sha256':B});units.assert_called_once_with(G,pre_start=True)
  with patch.object(h,'context',return_value=({}, {}, {}, B)),patch.object(h,'provenance'),patch.object(h,'validate_inputs'),patch.object(h,'helper_records',return_value={'writer_id':W,'binding_sha256':B}),patch.object(h,'load',return_value={'schema':1,'generation':G,'id':W,'binding_sha256':B}),patch.object(h,'validate_units') as units,patch.object(h.os.path,'lexists',side_effect=[True,False]):
   self.assertEqual(h.phase_verify(G,None),{'binding_sha256':B});units.assert_called_once_with(G,pre_start=False)
 def test_fixed_start_order(self):
  ids={'schema':1,'generation':G,'binding_sha256':B,'writer_id':W,'goose_id':GID};names=h.unit_names(G);calls=[]
  cat={'scope':{'task_id':'task'}};recipe={};stop={}
  def read(p,*args):return b'{}' if p.name.endswith('.writer.json') else (G+'\n'+B+'\n'+GID+'\n').encode()
  with patch.object(h,'context',return_value=(cat,recipe,stop,B)),patch.object(h,'provenance'),patch.object(h,'validate_inputs',return_value=({},{})),patch.object(h,'writer_seal',return_value={}),patch.object(h,'validate_units',return_value=names),patch.object(h,'scope_template',return_value={}),patch.object(h,'verify_scope_file'),patch.object(h,'helper_records',return_value=ids),patch.object(h,'rootfile',side_effect=read),patch.object(h,'read_created',side_effect=lambda g,r,b:W if r=='writer' else GID),patch.object(h,'engine_guard'),patch.object(h,'inspect'),patch.object(h,'guard'),patch.object(h,'directory'),patch.object(h,'secure_socket'),patch.object(h,'property_value',return_value='inactive'),patch.object(h,'start_container',side_effect=lambda g,r,i,b:calls.append(r)),patch.object(h,'start_unit',side_effect=lambda g,u,b,uid:calls.append(u)):
   self.assertEqual(h.phase_start(G,None),{'id':GID})
  self.assertEqual(calls,['writer',names[0],names[1],names[3],'goose'])
 def test_wrong_parent_or_wrong_recipe_refuses(self):
  mounts=[{'Type':'bind','Source':m['source'],'Destination':m['destination'],'RW':m['rw']} for m in h.expected_mounts(G,'writer')]
  env=['PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG=C.UTF-8','GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D','PYTHON_VERSION=3.11.18','PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290']
  o={'Id':W,'Name':'/sfactorywriter'+G.lower(),'Image':h.WRITER,'State':{'Status':'created','Pid':0},'Config':{'User':'2001:2001','Entrypoint':['/usr/local/bin/python3','-I','-B','/factory/nuc_fixed_writer.py'],'Cmd':None,'Env':env,'Labels':{'org.software-factory.generation':G,'org.software-factory.role':'writer'}},'HostConfig':{'CgroupParent':'sfactory'+G.lower()+'.slice','NetworkMode':'none','CgroupnsMode':'private','IpcMode':'private','PidMode':'','UTSMode':'','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'Binds':None,'Devices':None,'DeviceRequests':None,'SecurityOpt':['no-new-privileges'],'PidsLimit':64,'Memory':1073741824,'NanoCpus':1000000000,'RestartPolicy':{'Name':'no'},'Tmpfs':None},'Mounts':mounts}
  with patch.object(h,'fixed_run',side_effect=lambda *args,**kwargs:json.dumps([o]).encode()):
   self.assertEqual(h.inspect(G,'writer',W,'created'),o)
   o['HostConfig']['CgroupParent']='wrong.slice'
   with self.assertRaises(RuntimeError):h.inspect(G,'writer',W,'created')
   o['HostConfig']['CgroupParent']='sfactory'+G.lower()+'.slice';o['Config']['Entrypoint']=['/bin/sh']
   with self.assertRaises(RuntimeError):h.inspect(G,'writer',W,'created')
if __name__=='__main__':unittest.main()
