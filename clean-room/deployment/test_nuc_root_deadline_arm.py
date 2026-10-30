import copy,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import nuc_root_deadline_arm as d
class DeadlineTests(unittest.TestCase):
 def setUp(self):
  self.g='01M65DMY16BR2CQH9H8JKXC4TB';self.boot='boot';self.now=1_000_000_000_000
  self.catalog={'schema':1,'target_id':self.g,'task_id':self.g,'generation':self.g,'boot_id':self.boot,'cgroup_dev':1,'cgroup_ino':2}
  self.grant={'schema':1,'target_id':self.g,'boot_id':self.boot,'catalog_sha256':'a'*64,'issued_unix_ns':self.now-1,'expires_unix_ns':self.now+30_000_000_000,'max_duration_seconds':30,'purpose':'synthetic-canary-only'}
 def test_positive_and_margin(self):
  self.assertEqual(d.validate(self.grant,self.catalog,self.g,self.boot,self.now),25)
 def test_bad_scope_expiry_and_clock_are_denied(self):
  for key,value in [('purpose','production'),('boot_id','other'),('target_id','wrong'),('catalog_sha256','x'*64),('expires_unix_ns',self.now),('issued_unix_ns',self.now+1),('max_duration_seconds',241)]:
   bad=copy.deepcopy(self.grant);bad[key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):d.validate(bad,self.catalog,self.g,self.boot,self.now)
 def test_insufficient_margin_denied(self):
  self.grant['expires_unix_ns']=self.now+5_000_000_000
  with self.assertRaises(RuntimeError):d.validate(self.grant,self.catalog,self.g,self.boot,self.now)
 def test_unit_path_escaping(self):
  self.assertEqual(d.unit_path('abc.timer'),'/org/freedesktop/systemd1/unit/abc_2etimer')
 def test_fifo_is_rejected_without_waiting_for_writer(self):
  with tempfile.TemporaryDirectory() as temp:
   fifo=Path(temp)/'fifo';os.mkfifo(fifo,0o600)
   start=time.monotonic()
   with self.assertRaises(RuntimeError):d.pinned_json(fifo)
   self.assertLess(time.monotonic()-start,1)
 def test_ambiguous_manager_start_retains_intent_not_armed(self):
  with tempfile.TemporaryDirectory() as temp:
   spec={'target':self.g,'boot_id':self.boot,'grant_sha256':'b'*64,'catalog_sha256':'a'*64,'binary_sha256':d.BINARY_SHA,'duration_seconds':10,'expires_unix_ns':time.time_ns()+30_000_000_000,'timer':'test.timer','service':'test.service','purpose':'synthetic-canary-only'}
   def broken(*args,**kwargs):raise TimeoutError('lost manager response')
   with patch.object(d,'STATE',Path(temp)),patch.object(d,'plan',return_value=spec),patch.object(d,'run',side_effect=broken):
    with self.assertRaises(TimeoutError):d.arm(spec)
    self.assertTrue((Path(temp)/(self.g+'.deadline-intent.json')).exists())
    self.assertFalse((Path(temp)/(self.g+'.deadline-armed.json')).exists())
 def test_active_wake_and_fixed_exec_recorded(self):
  with tempfile.TemporaryDirectory() as temp:
   spec={'target':self.g,'boot_id':self.boot,'grant_sha256':'b'*64,'catalog_sha256':'a'*64,'binary_sha256':d.BINARY_SHA,'duration_seconds':10,'expires_unix_ns':time.time_ns()+30_000_000_000,'timer':'test.timer','service':'test.service','purpose':'synthetic-canary-only'}
   def manager(*args,**kwargs):
    if args[0].endswith('systemd-run'):return ''
    if args[0].endswith('busctl'):return 't '+str((time.monotonic_ns()+5_000_000_000)//1000)
    if 'ActiveState' in args:return 'active'
    if 'ExecStart' in args:return '{ path='+str(d.BINARY)+' ; argv[]='+str(d.BINARY)+' '+self.g+' ; ignore_errors=no ; }'
    if '-p' in args:
     key=args[args.index('-p')+1];unit=args[2]
     values={'LoadState':'loaded','Transient':'yes','Names':unit,'FragmentPath':'/run/systemd/transient/'+unit,'DropInPaths':'','User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','TasksMax':'16','MemoryMax':'134217728','CPUQuotaPerSecUSec':'500ms','RestrictAddressFamilies':'AF_UNIX','Restart':'on-failure','StartLimitIntervalUSec':'0','Unit':spec['service']}
     return values[key]
    raise AssertionError(args)
   with patch.object(d,'STATE',Path(temp)),patch.object(d,'plan',return_value=spec),patch.object(d,'run',side_effect=manager):
    self.assertEqual(d.arm(spec)['status'],'armed_not_admitted')
    self.assertTrue((Path(temp)/(self.g+'.deadline-intent.json')).exists())
    self.assertTrue((Path(temp)/(self.g+'.deadline-armed.json')).exists())
 def test_transient_alias_or_privilege_change_denied(self):
  spec={'target':self.g,'timer':'test.timer','service':'test.service'}
  for mutation in ('Names','NoNewPrivileges','MemoryMax'):
   def value(unit,key):
    values={'LoadState':'loaded','Transient':'yes','Names':unit,'FragmentPath':'/run/systemd/transient/'+unit,'DropInPaths':'','User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','TasksMax':'16','MemoryMax':'134217728','CPUQuotaPerSecUSec':'500ms','RestrictAddressFamilies':'AF_UNIX','Restart':'on-failure','StartLimitIntervalUSec':'0','Unit':'test.service','ExecStart':'{ path='+str(d.BINARY)+' ; argv[]='+str(d.BINARY)+' '+self.g+' ; ignore_errors=no ; }'}
    return 'tampered' if key==mutation else values[key]
   with self.subTest(mutation=mutation),patch.object(d,'property_value',side_effect=value),self.assertRaises(RuntimeError):d.verify_units(spec)
if __name__=='__main__':unittest.main()
