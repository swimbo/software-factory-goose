"""Isolated import checks for the fixed transition participants; no host effects."""
import ast
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import nuc_identity_bridge as bridge

ROOT = pathlib.Path(__file__).parent
STAGES = (
    'nuc_registry_retirement_coordinator', 'nuc_registry_restore_history',
    'nuc_registry_offline_backup', 'nuc_registry_restore_prepare',
    'nuc_registry_restore_verify', 'nuc_registry_unix_restate_provision',
    'nuc_registry_unix_restate_activate', 'nuc_registry_v5_catalog_publish',
    'nuc_registry_v5_runtime_activate', 'nuc_registry_v5_transition_plan',
    'nuc_registry_v5_unix_registration', 'nuc_registry_v5_replay_finish',
    'nuc_registry_v5_admission_producer_v2', 'nuc_registry_v5_finish_transition',
)
COMPONENTS = ('registry-history-capture', 'registry-offline-backup',
    'registry-restore-prepare', 'registry-restore-verify',
    'registry-unix-restate-provision', 'registry-unix-restate-activate',
    'registry-v5-transition-plan', 'registry-v5-unix-unit-upgrade',
    'registry-v5-catalog-publish', 'registry-v5-runtime-activate',
    'registry-v5-unix-attestation', 'registry-v5-unix-registration',
    'registry-v5-replay-finish', 'registry-v5-pending-admission',
    'registry-v5-finish-transition', 'registry-admission-package-v2-verify')
INJECTIONS = {
    'registry-unix-restate-provision': {'PROBE_SOURCE': 'nuc_registry_unix_restate_probe.py'},
    'registry-v5-transition-plan': {'PROBE_SOURCE': 'nuc_registry_old_deployment_probe.py'},
    'registry-v5-unix-registration': {'SOURCE': 'nuc_sdk5_unix_admin_fixed.py'},
    'registry-v5-replay-finish': {'LIVE_SOURCE': 'nuc_registry_live_history_probe.py', 'HANDLER_SOURCE': 'nuc_registry_v5_handler_replay_probe.py'},
}

def closure(stages):
    found = set()
    def visit(name):
        if name in found:
            return
        path = ROOT / (name + '.py')
        if not path.is_file():
            raise AssertionError('missing dependency: ' + name)
        found.add(name)
        tree = ast.parse(path.read_bytes(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith('nuc_'):
                        visit(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('nuc_'):
                visit(node.module)
    for stage in stages:
        visit(stage)
    return found

class TransitionClosure(unittest.TestCase):
    def test_composed_fixed_bridge_sources_load_and_plan_without_effects(self):
        import hashlib
        import json
        real_run = subprocess.run
        for component in COMPONENTS:
            with self.subTest(component=component), patch.object(sys, 'argv', ['bridge', '--' + component, 'plan']), patch.object(bridge.subprocess, 'run') as run:
                bridge.cli()
                remote = ast.parse(run.call_args.kwargs['input'])
                assignment = next(n for n in remote.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in n.targets))
                source = ast.literal_eval(assignment.value)
                self.assertEqual(bridge.canary_adapter_count(source), 1)
                expected = {key: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for key, name in INJECTIONS.get(component, {}).items()}
                code = '''import hashlib,json,os,sys\nsource=sys.stdin.read()\ndef audit(event,args):\n if event in ("subprocess.Popen","os.system","socket.connect","socket.bind","os.mkdir","os.remove","os.rename","os.chmod","os.chown"):\n  raise RuntimeError("effect: "+event)\n if event=="open" and len(args)>2 and isinstance(args[2],int) and args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):\n  raise RuntimeError("write")\nsys.addaudithook(audit)\nns={"__name__":"isolated_bridge"}\nexec(compile(source,"<bridge>","exec"),ns)\nfor key,digest in json.loads(sys.argv[1]).items():\n assert hashlib.sha256(ns[key]).hexdigest()==digest,key\nns["plan"]=lambda:{"scope":"test"}\ndef forbidden(*a): raise AssertionError("apply during plan")\nns["_canary_apply"]=forbidden\nassert ns["make_plan"](ns["Host"]("fixed"))["spec"]=={"scope":"test"}\n'''
                with tempfile.TemporaryDirectory() as tmp:
                    result = real_run([sys.executable, '-I', '-B', '-c', code, json.dumps(expected)], input=source, capture_output=True, text=True, cwd=tmp, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_restore_plan_holds_transition_lock(self):
        import contextlib
        import nuc_registry_restore_verify as restore
        state = []
        @contextlib.contextmanager
        def locked():
            state.append('enter')
            try:
                yield
            finally:
                state.append('exit')
        def read_plan():
            self.assertEqual(state, ['enter'])
            return {'ready': True}
        with patch.object(restore.backup, 'locked', locked), patch.object(restore, 'plan_locked', read_plan):
            self.assertEqual(restore.plan(), {'ready': True})
        self.assertEqual(state, ['enter', 'exit'])

    def test_isolated_imports_have_no_operational_effects(self):
        names = closure(STAGES)
        with tempfile.TemporaryDirectory() as tmp:
            for name in names:
                (pathlib.Path(tmp) / (name + '.py')).write_bytes((ROOT / (name + '.py')).read_bytes())
            code = '''import importlib,os,sys\nsys.path.insert(0,sys.argv[1])\ndef audit(event,args):\n if event in ("subprocess.Popen","os.system","socket.connect","socket.bind","os.mkdir","os.remove","os.rename","os.chmod","os.chown"):\n  raise RuntimeError("effect during import: "+event)\n if event == "open" and len(args)>2 and isinstance(args[2],int) and args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):\n  raise RuntimeError("write during import")\nsys.addaudithook(audit)\nfor name in sys.argv[2:]:\n m=importlib.import_module(name)\n assert callable(m.plan) and callable(m.apply),name\n'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, tmp, *STAGES], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
