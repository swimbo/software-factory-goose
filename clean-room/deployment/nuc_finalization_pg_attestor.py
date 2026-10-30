#!/usr/bin/env python3
"""UID1000-only fixed synthetic PostgreSQL listener attestation; no writes."""
import hashlib,json,os,pathlib,re,stat,subprocess,sys
PG=pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17')
ROOT=pathlib.Path('/tmp/sfactory-finalization-journal-pg')
POSTGRES=str(PG/'bin/postgres')
PORT=48292
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','LD_LIBRARY_PATH':str(PG/'lib')}
PINS={'postgres':'73984a14ebdb56a18b5032ea38a99716a64ded45168d6d80182b06f12d75bb29','psql':'2e80d774c4e3d9d4c9fce1bd2019493f6ebdc1679a75a071a475c8667612d8ca','pg_controldata':'388351a36be49fdbeb4c502b34ff592b625705bfbeaab98e31ecd3b02e694d5a'}
EXPECTED=[POSTGRES,'-D',str(ROOT),'-h','127.0.0.1','-p',str(PORT),'-k',str(ROOT)]
def require(ok,msg):
    if not ok: raise RuntimeError(msg)
def execute(args):
    p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=True)
    require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output limit')
    return p.stdout.decode('ascii')
def inspect():
    require(os.getuid()==1000 and os.geteuid()==1000 and os.getgid()==1000 and os.getegid()==1000,'fixture principal mismatch')
    st=ROOT.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o700,'PG root unsafe');root_identity=(st.st_dev,st.st_ino)
    fd=os.open(ROOT/'postmaster.pid',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());require(stat.S_ISREG(st.st_mode) and st.st_uid==1000 and st.st_nlink==1 and st.st_size<=4096,'PID file unsafe');parts=f.read(4097).decode('ascii').splitlines()
    require(len(parts)>=6 and parts[0].isdigit() and parts[1]==str(ROOT) and parts[3]==str(PORT) and parts[5]=='127.0.0.1','PID file mismatch')
    pid=int(parts[0]);proc=pathlib.Path('/proc')/str(pid)
    require(proc.stat().st_uid==1000 and os.readlink(proc/'exe')==POSTGRES,'postgres executable mismatch')
    command=(proc/'cmdline').read_bytes().split(b'\0');require(command[-1]==b'' and [x.decode('utf-8') for x in command[:-1]]==EXPECTED,'postgres argv mismatch')
    text=(proc/'stat').read_text();tail=text[text.rfind(')')+2:].split();require(len(tail)>19 and tail[19].isdigit(),'process start time unavailable');start=tail[19]
    listeners=[]
    for line in (proc/'net/tcp').read_text().splitlines()[1:]:
        row=line.split()
        if len(row)>9 and row[1]==f'0100007F:{PORT:04X}' and row[3]=='0A': listeners.append(row[9])
    require(len(listeners)==1,'listener unavailable or ambiguous')
    links=[]
    for fdpath in (proc/'fd').iterdir():
        try: links.append(os.readlink(fdpath))
        except FileNotFoundError: pass
    require('socket:['+listeners[0]+']' in links,'listener not owned by postgres')
    return {'pid':pid,'starttime':start,'socket_inode':listeners[0],'root_identity':root_identity}
def pin_tools():
    for parent in (PG,PG/'bin'):
        st=parent.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'PG tool directory unsafe')
    for name,digest in PINS.items():
        fd=os.open(PG/'bin'/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno());require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and 0<st.st_size<128*1024*1024,'PG tool unsafe')
            h=hashlib.sha256()
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
            require(h.hexdigest()==digest,'PG tool digest mismatch')
def main():
    status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(status.get('NoNewPrivs','').strip()=='1' and all(status.get(k,'').strip()=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),'attestor privilege mismatch')
    pin_tools()
    require(len(sys.argv)==1,'arguments forbidden')
    before=inspect()
    control=execute([str(PG/'bin/pg_controldata'),str(ROOT)])
    match=re.search(r'^Database system identifier:\s*(\d+)\s*$',control,re.MULTILINE);require(match is not None,'control system ID missing')
    sql=execute([str(PG/'bin/psql'),'-X','-h','127.0.0.1','-p',str(PORT),'-U','sfactory','-d','sfactory_verification','-v','ON_ERROR_STOP=1','-Atc','SELECT system_identifier FROM pg_control_system()']).strip()
    after=inspect();require(before==after and sql==match.group(1),'PG identity changed')
    print(json.dumps({'schema':1,'status':'attested','pid':before['pid'],'starttime':before['starttime'],'socket_inode':before['socket_inode'],'root_dev':before['root_identity'][0],'root_ino':before['root_identity'][1],'system_identifier':sql},sort_keys=True))
if __name__=='__main__':main()
