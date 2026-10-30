#!/usr/bin/env python3
"""Read-only proposed systemd canary plan. This file performs no installation or launch.

A separate reviewed root bootstrap must create the owned namespace, record its actual inode
and host inode in the protected config, provision isolated Restate/Postgres and then start the
listed units. The plan is not an activation capability or a test result.
"""
import json,sys

UNITS = {
 'software-factory-goose-canary-net.service': '''[Unit]\nDescription=Software factory isolated network namespace canary\n[Service]\nType=simple\nUser=root\nPrivateNetwork=yes\nExecStart=/usr/bin/sleep 300\n''',
 'software-factory-goose-canary-intake.socket': '''[Unit]\nDescription=Software factory canary intake socket\n[Socket]\nListenStream=/run/software-factory-goose/intake.sock\nSocketUser=root\nSocketGroup=1000\nSocketMode=0660\nFileDescriptorName=intake\nService=software-factory-goose-canary-runtime.service\n''',
 'software-factory-goose-canary-worker.socket': '''[Unit]\nDescription=Software factory canary worker socket\n[Socket]\nListenStream=/run/software-factory-goose/worker.sock\nSocketUser=root\nSocketGroup=sfgoose-worker\nSocketMode=0660\nFileDescriptorName=worker\nService=software-factory-goose-canary-runtime.service\n''',
 'software-factory-goose-canary-runtime.service': '''[Unit]\nDescription=Software factory private runtime canary\nRequires=software-factory-goose-canary-net.service\nAfter=software-factory-goose-canary-net.service\nJoinsNamespaceOf=software-factory-goose-canary-net.service\n[Service]\nType=simple\nUser=sfgoose-control\nPrivateNetwork=yes\nSockets=software-factory-goose-canary-intake.socket software-factory-goose-canary-worker.socket\nExecStart=/usr/local/libexec/software-factory-goose/private-runtime\nNoNewPrivileges=yes\n'''
}

def plan():
 return {'mode':'plan-only','units':UNITS,'fixed_paths':['/etc/software-factory-goose/runtime.json','/etc/software-factory-goose/evidence.json','/run/software-factory-goose/intake.sock','/run/software-factory-goose/worker.sock'],'prerequisites':['verify all proposed unit and file paths absent or explicitly owned by this canary','root-owned protected socket parent exists before socket units','anchor process actual host netns differs from the anchor private netns; root captures both device/inode pairs before minting config','exact named socket descriptor order and service UID verified from real systemd activation','separate disposable Restate and PostgreSQL are provisioned in the same private namespace before positive readiness','preserve existing services, cgroups, databases, credentials and retained original; withhold on ambiguity'],'limitations':['no units, files or accounts created by this plan','no runtime or production acceptance established']}

if __name__=='__main__':
 if sys.argv!=[sys.argv[0],'--plan']:raise SystemExit('only --plan is supported; no activation is implemented')
 print(json.dumps(plan(),sort_keys=True,indent=2))
