"""Read-only static diagnosis of retained closed generation; never authorizes launch."""
import hashlib,json,os,pathlib,time
import nuc_grant_sidecar_install as old
G='01M65NEH5T767H8Q5X71TTFR5S';ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
HELPER=old.PREFIX/'root-launch-host.py';SHA='3de11eef342e32c98c2d87659d647fc33547048b7ea80699e3bf117ec5d9a06d'
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 source=old.read(HELPER,0o755,SHA,1_000_000);ns={'__name__':'static_readonly'};exec(compile(source,'<pinned-root-helper>','exec'),ns)
 cat=ns['load'](ROOT/'launch-catalog'/(G+'.json'));recipe=ns['load'](ROOT/'launch-catalog'/(G+'.recipe.json'));stop=ns['load'](ROOT/'tasks'/(G+'.json'));verified=ns['load'](STATE/(G+'.grant-verified'))
 expiry=verified['reservation']['expires_at_ms'];boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();deadline,prod=ns['modules']()
 checks={}
 def test(name,fn):
  try:fn();checks[name]='pass'
  except Exception:checks[name]='fail'
 # Synthetic historical comparison only; cannot reopen the closed grant or authorize effects.
 test('historical_static_binding',lambda:prod.matches(cat,recipe,verified,stop,boot,G,expiry-1))
 test('image_provenance',lambda:ns['provenance'](recipe))
 test('engine_readonly_identity',ns['engine_guard'])
 test('inputs',lambda:ns['validate_inputs'](G,recipe))
 test('units',lambda:ns['validate_units'](G))
 test('provider_metadata',lambda:ns['scope_template'](G,cat,recipe,'0'*64))
 return {'component':'real-intloop-static-diagnostic','source_sha256':host.source_digest,'checks':checks,'closed_generation_unchanged':True,'historical_time_is_not_authority':True,'provider_called':False,'engine_started':False}
