import ast,sys,unittest
from unittest.mock import patch
import nuc_identity_bridge as bridge
class BridgeAdapters(unittest.TestCase):
 def test_non_json_stable_plan_is_refused_before_approval(self):
  for value in ({'inode':(29,12)},{'number':float('nan')},{1:'wrong key type'}):
   with self.subTest(value=value):
    ns={'plan':lambda:value,'apply':lambda _:self.fail('mutation reached')}
    exec(bridge.GRANT_JOURNAL_CANARY_ADAPTER,ns)
    with self.assertRaises((RuntimeError,ValueError)):ns['make_plan'](ns['Host']('fixed-source'))
 def test_json_stable_plan_survives_real_approval_roundtrip(self):
  import json
  seen=[];value={'inode':[29,12],'enabled':False,'value':None}
  ns={'plan':lambda:value,'apply':lambda approved:seen.append(approved)}
  exec(bridge.GRANT_JOURNAL_CANARY_ADAPTER,ns)
  host=ns['Host']('fixed-source');reviewed=json.loads(json.dumps(ns['make_plan'](host)))
  ns['apply'](host,reviewed)
  self.assertEqual(seen,[value])
 def test_extras_each_compose_exactly_one_adapter(self):
  components=('registry-retired-listener-install','registry-restore-history-install','registry-admission-probe-install','registry-admission-package-install','registry-v5-guarded-install','registry-v5-grant-install','registry-v5-launch-install','registry-eval-package-v2-install','registry-eval-package-v2-verify','unixdiag-peer-canary','backup-copy-cap-canary','unix-admin-h2-9086-final-continuation','unix-admin-h2-9086-orchestrator','unix-admin-h2-orchestrator','unix-admin-h2-epoch2-orchestrator','unix-admin-h2-classification-continuation','unix-admin-h2-postretire-continuation','unix-admin-failure-inventory','unix-admin-failure-snapshot','unix-admin-failure-summary','unix-admin-h2-contrast','unix-admin-failure-quiesce','h2-keeper-install','h2-keeper-activate','h2-keeper-control','h2-keeper-reconcile','unix-admin-h2-install','unix-admin-h2-activate','unix-admin-h2-sdk-install','unix-admin-h2-helpers-install','eval-canary3-provision','eval-canary3-service','eval-canary3-activate','eval-canary3-attest','eval-canary3-owner-loss','registry-gate-install','registry-v5-install','registry-gate-access-canary','registry-drain-schema','unix-admin-canary-install','unix-admin-canary-resume','unix-admin-canary-activate','unix-admin-canary-inventory','unix-admin-sdk-install','unix-admin-sdk-preflight','unix-admin-register-old','evidence-reader-install','evidence-reader-canary','authorization-canary-install','authorization-canary')
  for component in components:
   with self.subTest(component=component),patch.object(sys,'argv',['bridge','--'+component,'plan']),patch.object(bridge.subprocess,'run') as run:
    bridge.cli();remote=run.call_args.kwargs['input'];tree=ast.parse(remote)
    assignment=next(x for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE' for t in x.targets))
    source=ast.literal_eval(assignment.value)
    self.assertEqual(source.count('_canary_apply=apply'),1)
    functions=[x.name for x in ast.parse(source).body if isinstance(x,ast.FunctionDef)]
    self.assertEqual(functions.count('make_plan'),1)
if __name__=='__main__':unittest.main()
