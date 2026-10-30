#!/usr/bin/python3
"""Synthetic-only evaluator controller; never produces a production receipt."""
import pathlib,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
import nuc_registry_eval_client as client
import nuc_registry_eval_coordinator as controller
client.UNIT_NAME='software-factory-goose-eval-canary.service';client.UNIT=pathlib.Path('/etc/systemd/system')/client.UNIT_NAME
if __name__=='__main__':
 try:controller.main()
 except Exception:
  print('synthetic evaluation unavailable',file=sys.stderr);raise SystemExit(1)
