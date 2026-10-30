#!/usr/bin/env python3
"""Create-only PUBLIC canary installation candidate. Never starts units."""
import errno
import hashlib
import json
import os
import pathlib
import stat
import sys
import subprocess

SOURCE=pathlib.Path('/tmp/sfactory-openfile-canary-src')
BASE=pathlib.Path('/usr/local/libexec/software-factory-goose')
ETC=pathlib.Path('/etc/software-factory-goose')
UNITS=pathlib.Path('/etc/systemd/system')
STATE=pathlib.Path('/var/lib/software-factory-goose')
PUBLIC_DIR=ETC/'openfile-public-canary'
LEDGER=STATE/'openfile-public-canary'
PROGRAM=BASE/'nuc-openfile-public-canary.py'
UNIT=UNITS/'sfactory-openfile-public-canary.service'
PUBLIC=b'SFACTORY-PUBLIC-OPENFILE-20261030\n'
PROGRAM_SHA='7e74a19adb15fee937196d4c5e98dc0f0e1732c9d09379bfd42b29f04b20cfce'
UNIT_SHA='481e09ff61f6ba125d8abad28dfb15f9a1f205313b56bbd91bfe607955d863fa'


def no_acl(fd, directory):
    for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
        try:os.getxattr(fd,name)
        except OSError as exc:
            if exc.errno==errno.ENODATA:continue
            raise RuntimeError('ACL unavailable') from None
        raise RuntimeError('ACL unavailable')


def directory(path,owner=0,mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if (st.st_uid!=owner or (owner==0 and st.st_gid!=0) or st.st_mode&0o022
                or mode is not None and stat.S_IMODE(st.st_mode)!=mode):raise RuntimeError('directory unavailable')
        no_acl(fd,True)
    finally:os.close(fd)


def source(name,expected):
    directory(SOURCE,1000,0o700)
    fd=os.open(SOURCE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or not 0<s.st_size<=65536:raise RuntimeError('source unavailable')
        no_acl(fd,False)
        data=os.read(fd,65537)
        if len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('source unavailable')
        return data
    finally:os.close(fd)


def trusted_tmp():
    fd=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o1777:raise RuntimeError('temporary directory unavailable')
        no_acl(fd,True)
    finally:os.close(fd)


def plan():
    if os.geteuid()!=0:raise RuntimeError('root required')
    for path in map(pathlib.Path,('/','/usr','/usr/local','/usr/local/libexec','/etc','/etc/systemd','/var','/var/lib')):
        directory(path)
    for path in (BASE,ETC,UNITS,STATE):directory(path)
    trusted_tmp()
    if any(os.path.lexists(path) for path in (PUBLIC_DIR,LEDGER,PROGRAM,UNIT)):
        raise RuntimeError('target or prior intent exists')
    program=source('nuc_openfile_public_canary.py',PROGRAM_SHA)
    unit=source('openfile-public-canary.service.in',UNIT_SHA)
    anchor_path=pathlib.Path('/run/software-factory-goose/host-netns.json')
    fd=os.open(anchor_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or not 0<st.st_size<1024:raise RuntimeError('host observation unavailable')
        no_acl(fd,False); observation=json.loads(os.read(fd,1024))
    finally:os.close(fd)
    if set(observation)!={'version','role','pid','uid','netns_dev','netns_ino'} or observation['version']!=1 or observation['role']!='host' or observation['uid']!=0:raise RuntimeError('host observation unavailable')
    unit_name='software-factory-goose-private-host-net.service'
    r=subprocess.run(['/usr/bin/systemctl','show',unit_name,'-p','MainPID','-p','ActiveState','-p','User','-p','ExecStart'],capture_output=True,text=True,check=True,timeout=5)
    props=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
    if props.get('ActiveState')!='active' or props.get('User')!='root' or props.get('MainPID')!=str(observation['pid']) or '/usr/local/libexec/software-factory-goose/private-netns-anchor.py host' not in props.get('ExecStart',''):raise RuntimeError('host anchor unavailable')
    program_path=BASE/'private-netns-anchor.py'
    fd=os.open(program_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);no_acl(fd,False)
        if st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022 or st.st_nlink!=1 or hashlib.sha256(os.read(fd,65537)).hexdigest()!='3eb0162f005b961be44c381e142d16dc7ded34b2d5eca81ab9f7373fc1858123':raise RuntimeError('host anchor unavailable')
    finally:os.close(fd)
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    spec={'version':1,'purpose':'public-only-openfile-netns-canary','boot_id':boot,
          'network_device':observation['netns_dev'],'network_inode':observation['netns_ino'],
          'program_sha256':PROGRAM_SHA,'unit_sha256':UNIT_SHA,
          'targets':[str(PUBLIC_DIR),str(LEDGER),str(PROGRAM),str(UNIT)],
          'start_or_reload':'none','credential_access':'none'}
    return spec,program,unit


def syncdir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def create(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode)
        if os.fstat(fd).st_uid!=0 or os.fstat(fd).st_gid!=0:raise RuntimeError('owner unavailable')
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0:raise RuntimeError('write unavailable')
            view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    syncdir(path.parent)


def apply(reviewed):
    spec,program,unit=plan()
    if reviewed!=spec:raise RuntimeError('reviewed plan changed')
    os.mkdir(LEDGER,0o700);syncdir(STATE)
    plan_hash=hashlib.sha256(json.dumps(spec,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    create(LEDGER/'intent.json',json.dumps({'plan':spec,'plan_sha256':plan_hash},sort_keys=True).encode(),0o600)
    os.mkdir(PUBLIC_DIR,0o700);syncdir(ETC)
    create(PUBLIC_DIR/'public',PUBLIC,0o600)
    create(PUBLIC_DIR/'expected',json.dumps({'network_device':spec['network_device'],'network_inode':spec['network_inode']},sort_keys=True).encode(),0o600)
    create(PROGRAM,program,0o755)
    create(UNIT,unit,0o644)
    create(LEDGER/'receipt.json',json.dumps({'plan_sha256':plan_hash,'status':'installed_not_started'},sort_keys=True).encode(),0o600)
    return {'plan_sha256':plan_hash,'status':'installed_not_started'}


def main():
    if sys.argv != [sys.argv[0],'plan']:raise RuntimeError('plan only; apply through reviewed root bridge')
    print(json.dumps(plan()[0],sort_keys=True))

if __name__=='__main__':main()
