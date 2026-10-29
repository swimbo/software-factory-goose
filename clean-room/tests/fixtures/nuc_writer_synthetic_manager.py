#!/usr/bin/env python3
"""One retained, systemd-owned synthetic writer integration; no live provider."""
import os,pathlib,subprocess,uuid,sys
ROOT=pathlib.Path('/tmp/sfactory-writer-preflight.WdzouOy1')
PROMPT='Synthetic fixture only: call factory write_files once with both requested files, then finish.'
def main():
 if os.getuid()!=1000:raise RuntimeError('unexpected owner')
 if len(sys.argv)!=2 or sys.argv[1] not in ('wrong_tool','duplicate_keys','wrong_tool2','large_sse','large_sse2','large_sse3','large_sse_hold'):raise RuntimeError('explicit negative control required')
 mode=sys.argv[1];negative='wrong_tool' if mode=='wrong_tool2' else ('' if mode in ('large_sse','large_sse2','large_sse3','large_sse_hold') else mode);root=ROOT/('batch-'+mode);root.mkdir(mode=0o700)
 candidate=ROOT/('candidate-'+mode);candidate.mkdir(mode=0o777);candidate.chmod(0o777)
 unit='sfactory-writer-synth-'+uuid.uuid4().hex+'.service'
 fd=os.open(root/'unit',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:out.write(unit+'\n');out.flush();os.fsync(out.fileno())
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 env={'SFACTORY_FIXTURE_CODE_ROOT':str(ROOT),'SFACTORY_FIXTURE_JOURNAL':'unused','SFACTORY_WRITER_PREFLIGHT':'1','SFACTORY_WRITER_SNAPSHOT':str(ROOT/'snapshot.json'),'SFACTORY_WRITER_CANDIDATE':str(candidate),'SFACTORY_WRITER_NEGATIVE':negative,'SFACTORY_LARGE_SSE_PREFLIGHT':'1' if mode in ('large_sse','large_sse2','large_sse3','large_sse_hold') else '0','SFACTORY_TASK_PROMPT':PROMPT,'SFACTORY_BATCH_ROOT':str(root)}
 if mode=='large_sse_hold':env['SFACTORY_FIXTURE_HOLD']='1'
 cmd=['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,'--property=RuntimeMaxSec=120s','--property=TimeoutStopSec=60s','--property=KillMode=control-group','--property=StandardOutput=append:'+str(root/'output.log'),'--property=StandardError=append:'+str(root/'output.log'),'--property=ExecStopPost=/usr/bin/python3 '+str(ROOT/'nuc_live_batch_recovery.py')+' '+str(root)]
 cmd.extend('--setenv='+key+'='+value for key,value in env.items());cmd.extend(['/usr/bin/python3',str(ROOT/'nuc_goose_relay_batch.py')])
 # On failure or timeout retain the unit identity and root; never retry.
 subprocess.run(cmd,check=True,timeout=10,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 print(unit,flush=True)
if __name__=='__main__':main()
