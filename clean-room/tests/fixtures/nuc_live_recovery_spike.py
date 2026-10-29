#!/usr/bin/env python3
"""Exercise the live recovery helper against the synthetic Goose systemd fixture."""
import pathlib, subprocess, sys
source=(pathlib.Path(__file__).parent/'nuc_goose_batch_systemd.py').read_text()
a=source.index("recovery=temp/'recovery.py'"); b=source.index('\ntry:\n prior=',a)
source=source[:a]+"recovery=ROOT/'nuc_live_batch_recovery.py'"+source[b:]
source=source.replace("+' '+str(temp/'recovered')", "")
source=source.replace("(temp/'recovered').exists()", "(batchroot/'recovery-verified').exists()")
source=source.replace("result=(temp/'recovered').read_text()", "result=(batchroot/'recovery-verified').read_text().strip()")
source=source.replace("if result!='OK':", "if result!='verified empty worker slice':")
r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=source,text=True,timeout=160)
sys.exit(r.returncode)
