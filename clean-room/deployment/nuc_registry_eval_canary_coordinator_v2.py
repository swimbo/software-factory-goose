#!/usr/bin/python3
"""Synthetic-only coordinator using fixed paths in a search-only directory."""
import importlib.util,pathlib,sys
ROOT=pathlib.Path('/usr/local/libexec/software-factory-goose/evaluator')
def load(name):
 path=ROOT/(name+'.py');spec=importlib.util.spec_from_file_location(name,path)
 if spec is None or spec.loader is None:raise RuntimeError('fixed module unavailable')
 module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
load('nuc_registry_evaluator')
client=load('nuc_registry_eval_client')
controller=load('nuc_registry_eval_coordinator')
client.UNIT_NAME='software-factory-goose-eval-canary.service';client.UNIT=pathlib.Path('/etc/systemd/system')/client.UNIT_NAME
if __name__=='__main__':
 try:controller.main()
 except Exception:
  print('synthetic evaluation unavailable',file=sys.stderr);raise SystemExit(1)
