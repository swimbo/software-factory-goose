import ast,inspect,sys,unittest
from unittest.mock import patch
import nuc_identity_bridge as bridge
class EvaluatorAdapterTests(unittest.TestCase):
 def test_registered_components_compose_without_duplicate_adapters(self):
  tree=ast.parse(inspect.getsource(bridge.cli));components=set()
  for node in ast.walk(tree):
   is_initial=isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='extras' for t in node.targets)
   is_update=isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='extras' and node.func.attr=='update'
   mapping=node.value if is_initial else node.args[0] if is_update and node.args else None
   if isinstance(mapping,ast.Dict):
    for key,value in zip(mapping.keys,mapping.values):
     if isinstance(key,ast.Constant) and isinstance(key.value,str) and isinstance(value,ast.Constant) and isinstance(value.value,str) and value.value.endswith('.py'):components.add(key.value)
  self.assertGreaterEqual(len(components),40)
  for component in components:
   with self.subTest(component=component),patch.object(sys,'argv',(['bridge','plan'] if component=='identity' else ['bridge','--'+component,'plan'])),patch.object(bridge.subprocess,'run') as run:
    bridge.cli();remote=ast.parse(run.call_args.kwargs['input'])
    assignment=next(n for n in remote.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE' for t in n.targets))
    source=ast.literal_eval(assignment.value)
    self.assertLessEqual(bridge.canary_adapter_count(source),1)
 def test_duplicate_adapter_is_rejected_locally(self):
  source='def apply(value):return value\ndef plan():return {}\n'
  once=source+bridge.GRANT_JOURNAL_CANARY_ADAPTER
  self.assertEqual(bridge.canary_adapter_count(once),1)
  bridge.require_single_canary_adapter(once)
  with self.assertRaisesRegex(ValueError,'no remote operation'):
   bridge.require_single_canary_adapter(once+bridge.GRANT_JOURNAL_CANARY_ADAPTER)
