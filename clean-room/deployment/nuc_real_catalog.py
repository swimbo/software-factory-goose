"""Build the fixed fresh hello catalog from a validated root-owned baseline receipt."""
import hashlib,json,re
from nuc_real_repo_install import REQUIREMENTS
INTENT='01M65NEH5T1Z0JWW2YCV44DY01';TASK='01M65NEH5TBPKNDW21TE6FR3XA';GENERATION='01M65NEH5T767H8Q5X71TTFR5S'
QUEUE='hello-int-loop-20261030';WORKER='hello-int-loop-worker';REPOSITORY='hello-int-loop-20261030'

def packed(obj):return json.dumps(obj,ensure_ascii=False,separators=(',',':')).encode()

def build(original,baseline):
 if not re.fullmatch(r'[0-9a-f]{40}',baseline):raise ValueError('invalid baseline')
 request={'schema_version':1,'repository':REPOSITORY,'target_ref':'refs/heads/main','base_revision':baseline,'intent':REQUIREMENTS.strip(),'acceptance_criteria':['The hello CLI meets requirements.md.','The stdlib unittest suite passes.','Only hello.py and test_hello.py are added.']}
 # The task is a tightly scoped new repository with executable criteria and no external dependencies.
 facts={'spec_clarity':1.0,'blast_radius':0.0,'novelty':0.0,'reversibility':0.0,'has_codified_knowledge':True,'fatal':False}
 principal=original['principal'];evidence=packed({'principal':principal,'request':request,'facts':facts});evidence_sha=hashlib.sha256(evidence).hexdigest()
 digest=hashlib.sha256(packed([principal,QUEUE,INTENT,TASK,request,facts,evidence_sha])).hexdigest()
 scope={'task_id':TASK,'intent_id':INTENT,'queue_id':QUEUE,'generation':GENERATION,'spec':{'repository':REPOSITORY,'base_revision':baseline},'worker_id':WORKER,'catalog_sha256':digest}
 config=dict(original);config.update(sdk_port=9083,worker_id=WORKER,queue_id=QUEUE,intent_id=INTENT,task_id=TASK,request=request,facts=facts,evidence_sha256=evidence_sha,launch_scope=scope)
 return config,evidence
