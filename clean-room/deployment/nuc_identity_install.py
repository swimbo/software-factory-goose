#!/usr/bin/env python3
"""Explicit, host-root PLAN/APPLY for factory identities; no service activation.

PLAN emits JSON to stdout. APPLY accepts that exact JSON on stdin and revalidates
before changing anything. Run only from the reviewed root bridge. A failure after
an action retains the private journal; this tool never rolls back account databases.
"""
import hashlib
import json
import os
import pathlib
import pwd
import grp
import stat
import subprocess
import sys

SCAN_LIMIT = 3_000_000

ROLES = ('sfgoose-control', 'sfgoose-worker', 'sfgoose-eval', 'sfgoose-brake', 'sfgoose-journal')
TARGETS = ('/etc/software-factory-goose', '/var/lib/software-factory-goose',
           '/usr/local/libexec/software-factory-goose')
ANCESTORS = ('/', '/etc', '/var', '/var/lib', '/usr', '/usr/local', '/usr/local/libexec')
STATE = TARGETS[1]

class Refused(Exception):
    pass

class Host:
    def __init__(self, source_digest=None):
        self.source_digest = source_digest
    def require_root(self):
        if os.geteuid() != 0:
            raise Refused('requires host root')
    def machine(self):
        return hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest()
    def accounts(self):
        return ({p.pw_name: p.pw_uid for p in pwd.getpwall()},
                {g.gr_name: g.gr_gid for g in grp.getgrall()})
    def identity(self, path):
        try:
            s = os.lstat(path)
        except FileNotFoundError:
            return None
        return {'dev':s.st_dev, 'ino':s.st_ino, 'uid':s.st_uid, 'gid':s.st_gid,
                'mode':stat.S_IMODE(s.st_mode), 'directory':stat.S_ISDIR(s.st_mode),
                'symlink':stat.S_ISLNK(s.st_mode)}
    def check_acl(self, path):
        out = subprocess.run(['/usr/bin/getfacl', '-cp', '--', path], check=True,
                             capture_output=True, text=True).stdout
        entries = [x for x in out.splitlines() if x and not x.startswith('#')]
        # Reject all extended/default ACLs. ACL group permissions cannot exceed mode.
        if len(entries) != 3 or not all(x.startswith(y) for x,y in zip(entries, ('user::','group::','other::'))):
            raise Refused('extended or default ACL on ancestor')
    def db(self, name):
        path = '/etc/' + name
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise Refused('unsafe account database')
        data = pathlib.Path(path).read_bytes()
        for line in data.splitlines():
            fields=line.split(b':')
            if len(fields) < 4 or fields[1] not in (b'', b'x', b'*', b'!', b'!!'):
                raise Refused('account database has non-marker password field')
        return data
    def secret_db(self, name):
        # Root-memory-only comparison: no file content enters a plan, journal,
        # exception, hash, subprocess argument or output. Never follow links.
        if name not in ('shadow', 'gshadow'):
            raise Refused('private account database verification failed')
        fd = None
        try:
            fd = os.open('/etc/' + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            info = os.fstat(fd)
            shadow_gid = grp.getgrnam('shadow').gr_gid
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid not in (0,shadow_gid)
                    or stat.S_IMODE(info.st_mode) & 0o137 or info.st_nlink != 1
                    or info.st_size > 8 * 1024 * 1024):
                raise Refused('private account database verification failed')
            result = subprocess.run(['/usr/bin/getfacl','-cp','--','/proc/self/fd/'+str(fd)],
                                    pass_fds=(fd,),check=True,capture_output=True,text=True)
            entries = [x for x in result.stdout.splitlines() if x and not x.startswith('#')]
            if len(entries) != 3 or not all(x.startswith(y) for x,y in zip(entries,('user::','group::','other::'))):
                raise Refused('private account database verification failed')
            parts=[]
            total=0
            while True:
                chunk=os.read(fd, min(65536, 8 * 1024 * 1024 + 1 - total))
                if not chunk: break
                parts.append(chunk); total+=len(chunk)
                if total > 8 * 1024 * 1024:
                    raise Refused('private account database verification failed')
            return b''.join(parts)
        except (OSError, KeyError, subprocess.SubprocessError):
            raise Refused('private account database verification failed') from None
        finally:
            if fd is not None: os.close(fd)
    def protected_daemon_dirs(self):
        try:
            root = subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock',
                                   'info','--format','{{.DockerRootDir}}'],
                                  check=True,capture_output=True,text=True,timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            raise Refused('Docker root directory verification failed') from None
        if root != '/var/lib/docker':
            raise Refused('unexpected Docker root directory')
        result={}
        for path in ('/var/lib/docker','/var/lib/containerd'):
            info=self.identity(path)
            if (not info or not info['directory'] or info['symlink'] or info['uid'] != 0
                    or info['gid'] != 0 or info['mode'] & 0o027):
                raise Refused('unsafe daemon data exclusion')
            self.check_acl(path)
            result[path]=info
        return result
    def occupied_filesystem_ids(self):
        # Only root-protected daemon data are excluded; a bridge's transient
        # overlay paths under those roots cannot destabilize plan comparison.
        protected = self.protected_daemon_dirs()
        occupied, scope = scan_metadata(['/', '/home', '/tmp'],
                                        {'/proc','/sys','/dev','/run'},
                                        set(protected))
        if self.protected_daemon_dirs() != protected:
            raise Refused('daemon data exclusion changed during inventory')
        scope['excluded_protected_daemon_paths'] = protected
        return occupied, scope
    def mkdir(self, path, mode):
        os.mkdir(path, mode)
        os.chmod(path, mode)
        self.syncdir(os.path.dirname(path))
    def chown(self, path, uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)
        self.syncdir(os.path.dirname(path))
    def syncdir(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    def write(self, path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        self.syncdir(os.path.dirname(path))
    def add_group(self, role, gid):
        subprocess.run(['/usr/sbin/groupadd','--gid',str(gid),role],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def add_user(self, role, uid, gid):
        subprocess.run(['/usr/sbin/useradd','--system','--no-log-init','--uid',str(uid),'--gid',str(gid),
                        '--home-dir','/nonexistent','--no-create-home',
                        '--shell','/usr/sbin/nologin','--no-user-group',
                        '--password','!',role],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def verify_user(self, role, uid, gid):
        entry = pwd.getpwnam(role)
        status = subprocess.run(['/usr/bin/passwd','-S',role],check=True,
                                capture_output=True,text=True).stdout.split()
        supplemental = [g.gr_name for g in grp.getgrall() if role in g.gr_mem]
        if (entry.pw_uid != uid or entry.pw_gid != gid or entry.pw_shell != '/usr/sbin/nologin'
                or entry.pw_dir != '/nonexistent' or len(status) < 2 or status[1] != 'L'
                or supplemental):
            raise Refused('created account does not satisfy locked no-login contract')
    def script_digest(self):
        if self.source_digest is not None:
            return self.source_digest
        return hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()


def make_plan(host):
    host.require_root()
    users, groups = host.accounts()
    if users.get('bo') != 1000:
        raise Refused('expected existing bo operator UID 1000')
    if any(x in users or x in groups for x in ROLES):
        raise Refused('role account or group collision')
    ancestors = {}
    for path in ANCESTORS:
        info = host.identity(path)
        if not info or not info['directory'] or info['symlink'] or info['uid'] != 0 or info['mode'] & 0o022:
            raise Refused('unsafe installation ancestor')
        host.check_acl(path)
        ancestors[path] = info
    if any(host.identity(p) is not None for p in TARGETS):
        raise Refused('target collision or partial prior installation')
    occupied, scan_scope = host.occupied_filesystem_ids()
    used = set(users.values()) | set(groups.values()) | occupied
    available = [n for n in range(2000, 60000) if n not in used][:len(ROLES)]
    if len(available) != len(ROLES):
        raise Refused('insufficient unused identities')
    identities = [{'name':r, 'uid':n, 'gid':n} for r,n in zip(ROLES,available)]
    dbhash = {n:hashlib.sha256(host.db(n)).hexdigest() for n in ('passwd','group')}
    return {'schema':1, 'machine':host.machine(), 'source_sha256':host.script_digest(),
            'operator_uid':1000, 'identities':identities, 'ancestors':ancestors,
            'account_db_sha256':dbhash, 'filesystem_scan_scope':scan_scope, 'targets':list(TARGETS),
            'actions':['create private state directory', 'back up passwd and group without secret fields',
                       'create five groups and locked nologin users',
                       'create root-owned config and executable directories',
                       'create private journal owned by journal identity'],
            'rollback':'no automatic rollback or global account database restore; inspect retained per-action journal'}


def scan_metadata(roots, skipped, excluded):
    # Metadata only; never read content or follow symlinks. An excluded path
    # must already have been validated by the caller, never user-supplied.
    occupied, seen, boundary_hashes = set(), set(), set()
    scans = []
    count = 0
    for root in roots:
        try: root_stat = os.lstat(root)
        except FileNotFoundError: continue
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
            raise Refused('unsafe filesystem inventory root')
        scans.append({'root':root,'dev':root_stat.st_dev})
        stack=[(root,root_stat.st_dev)]
        while stack:
            path,device = stack.pop()
            if path in skipped or path in excluded: continue
            info = os.lstat(path)
            if info.st_dev != device:
                boundary_hashes.add(hashlib.sha256(os.fsencode(path)).hexdigest())
                continue
            count += 1
            if count > SCAN_LIMIT: raise Refused('filesystem inventory limit reached')
            occupied.update((info.st_uid,info.st_gid))
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): continue
            identity=(info.st_dev,info.st_ino)
            if identity in seen: continue
            seen.add(identity)
            with os.scandir(path) as entries:
                for entry in entries:
                    stack.append((os.path.join(path,entry.name),device))
    return occupied, {'roots':scans,'skipped_special':sorted(skipped),
                      'different_device_path_sha256':sorted(boundary_hashes),
                      'entry_limit':SCAN_LIMIT}


def assert_existing_records_preserved(before, after, added=None):
    old = before.splitlines(keepends=True)
    new = after.splitlines(keepends=True)
    if added is None:
        if old != new: raise Refused('existing account database records changed')
        return
    prefix = added.encode() + b':'
    added_lines = [line for line in new if line.startswith(prefix)]
    if len(added_lines) != 1 or [line for line in new if not line.startswith(prefix)] != old:
        raise Refused('existing account database records changed')


def apply(host, plan):
    if plan != make_plan(host):
        raise Refused('plan or host state changed')
    host.mkdir(STATE, 0o711)
    host.write(STATE + '/plan.json', json.dumps(plan,sort_keys=True,indent=2).encode())
    # This journal is deliberately retained after all failures. The first mkdir itself is
    # the fail-closed installation marker; a crash before its first record is partial state.
    seq = 0
    def action(label, fn):
        nonlocal seq
        seq += 1
        stem = f'{STATE}/{seq:02d}'
        host.write(stem + '-intent.json', json.dumps({'action':label},sort_keys=True).encode())
        fn()
        host.write(stem + '-done.json', json.dumps({'action':label,'done':True},sort_keys=True).encode())
    for name in ('passwd','group'):
        data = host.db(name)
        if hashlib.sha256(data).hexdigest() != plan['account_db_sha256'][name]:
            raise Refused('account database changed before backup')
        action('backup ' + name, lambda name=name,data=data: host.write(STATE + '/backup-' + name, data))
    for item in plan['identities']:
        role,uid,gid = item['name'],item['uid'],item['gid']
        users,groups = host.accounts()
        if role in users or role in groups or uid in users.values() or gid in groups.values():
            raise Refused('identity collision before group creation')
        def create_group_and_verify():
            old_passwd,old_group=host.db('passwd'),host.db('group')
            old_shadow,old_gshadow=host.secret_db('shadow'),host.secret_db('gshadow')
            host.add_group(role,gid)
            assert_existing_records_preserved(old_passwd,host.db('passwd'))
            assert_existing_records_preserved(old_group,host.db('group'),role)
            assert_existing_records_preserved(old_shadow,host.secret_db('shadow'))
            assert_existing_records_preserved(old_gshadow,host.secret_db('gshadow'),role)
        action('create group ' + role, create_group_and_verify)
        users,groups = host.accounts()
        if role in users or uid in users.values() or groups.get(role) != gid:
            raise Refused('identity changed before user creation')
        def create_and_verify():
            old_passwd,old_group=host.db('passwd'),host.db('group')
            old_shadow,old_gshadow=host.secret_db('shadow'),host.secret_db('gshadow')
            host.add_user(role,uid,gid)
            assert_existing_records_preserved(old_passwd,host.db('passwd'),role)
            assert_existing_records_preserved(old_group,host.db('group'))
            assert_existing_records_preserved(old_shadow,host.secret_db('shadow'),role)
            assert_existing_records_preserved(old_gshadow,host.secret_db('gshadow'))
            host.verify_user(role,uid,gid)
        action('create locked user ' + role, create_and_verify)
        users,groups = host.accounts()
        if users.get(role) != uid or groups.get(role) != gid:
            raise Refused('created identity mismatch')
    for path in (TARGETS[0], TARGETS[2]):
        if host.identity(path) is not None:
            raise Refused('target appeared during apply')
        mode = 0o711 if path == TARGETS[0] else 0o755
        action('create ' + path, lambda path=path,mode=mode:host.mkdir(path,mode))
    journal = STATE + '/journal'
    item = plan['identities'][-1]
    action('create private journal', lambda:host.mkdir(journal,0o700))
    action('assign private journal owner', lambda:host.chown(journal,item['uid'],item['gid']))
    host.write(STATE + '/complete.json', b'{"complete":true}\n')


def main():
    host=Host()
    if sys.argv[1:] == ['plan']:
        print(json.dumps(make_plan(host),sort_keys=True,indent=2))
    elif sys.argv[1:] == ['apply']:
        plan=json.load(sys.stdin)
        apply(host,plan)
        print('identity installation complete; no services enabled')
    else:
        raise Refused('usage: nuc_identity_install.py plan|apply')

if __name__ == '__main__':
    try: main()
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as e:
        print('REFUSED: ' + str(e),file=sys.stderr)
        sys.exit(1)
