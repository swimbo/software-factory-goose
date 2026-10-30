#!/usr/bin/env python3
"""Fixed create-only synthetic root evidence canary; review-only until hash pinned.

Never opens task state, provider data or credentials. Partial/ambiguous outcomes
retain the intent and all files; no broad cleanup or automatic retry.
"""
import errno, hashlib, json, os, pathlib, stat, subprocess, sys, time

ROOT = pathlib.Path('/etc/software-factory-goose/evidence-reader-canary')
BINARY = pathlib.Path('/usr/local/libexec/software-factory-goose/root_evidence_reader_canary')
PARENT_INTENT = ROOT.parent / 'evidence-reader-canary.intent'
# Locked/offline isolated NUC build; installation is a separate create-only step.
BINARY_SHA256 = '977d624102840bdeb4db4a700d44bdc5af9f5ca42442702da80c566b111988d8'
PUBLIC = b'{"canary":true}\n'
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C'}

def require(condition, message):
    if not condition: raise RuntimeError(message)

def no_acl(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        for name in ('system.posix_acl_access', 'system.posix_acl_default'):
            try: os.getxattr(fd, name)
            except OSError as exc:
                if exc.errno != errno.ENODATA: raise RuntimeError('ACL state unavailable') from None
            else: raise RuntimeError('ACL present')
    finally: os.close(fd)

def ancestors(path):
    for parent in path.parents:
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and not st.st_mode & 0o022, 'untrusted parent')
        no_acl(parent)

def fixed_tool(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o755, 'untrusted executable')
    ancestors(path); no_acl(path)

def binary_digest():
    fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o755 and st.st_size <= 64 * 1024 * 1024, 'untrusted canary binary')
        ancestors(BINARY); no_acl(BINARY)
        return hashlib.sha256(f.read(64 * 1024 * 1024 + 1)).hexdigest()

def plan():
    require(os.geteuid() == 0, 'root required')
    require(len(BINARY_SHA256) == 64 and all(c in '0123456789abcdef' for c in BINARY_SHA256), 'binary digest unpinned')
    ancestors(ROOT)
    require(not os.path.lexists(ROOT), 'canary path already exists')
    require(not os.path.lexists(PARENT_INTENT), 'canary intent already exists')
    for tool in (pathlib.Path('/usr/bin/setfacl'), pathlib.Path('/usr/bin/systemd-run'), pathlib.Path('/usr/bin/systemctl'), pathlib.Path('/usr/bin/systemd-analyze')): fixed_tool(tool)
    require(binary_digest() == BINARY_SHA256, 'binary digest mismatch')
    probe = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', 'LoadState', '--value'], env=ENV, capture_output=True, timeout=5, check=False)
    require(probe.returncode == 0 and probe.stdout.strip() in (b'', b'not-found'), 'canary unit already exists or unavailable')
    dropins = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', 'DropInPaths', '--value'], env=ENV, capture_output=True, timeout=5, check=False)
    require(dropins.returncode == 0 and not dropins.stdout.strip(), 'canary drop-ins present or unavailable')
    # Check generic, prefix and exact service drop-ins before starting a unit. Unit
    # properties are rechecked afterwards; no pre-existing drop-in is trusted.
    paths = subprocess.run(['/usr/bin/systemd-analyze', '--system', 'unit-paths'], env=ENV, capture_output=True, timeout=5, check=True).stdout.decode().splitlines()
    require(paths and len(paths) <= 64 and all(pathlib.Path(p).is_absolute() for p in paths), 'unit search path unavailable')
    for unit_root in paths:
        for suffix in ('service.d', 'sfactory-.service.d', 'sfactory-evidence-.service.d', 'sfactory-evidence-reader-.service.d', 'sfactory-evidence-reader-canary.service.d'):
            directory = pathlib.Path(unit_root) / suffix
            require(not os.path.lexists(directory) or (directory.is_dir() and not directory.is_symlink() and not any(directory.iterdir())), 'unit drop-in directory is not empty')
    return {'schema': 1, 'purpose': 'public-synthetic-reader-only', 'root': str(ROOT), 'binary': str(BINARY), 'binary_sha256': BINARY_SHA256, 'unit': 'sfactory-evidence-reader-canary.service', 'files': ['valid.json', 'bad-mode.json', 'bad-acl.json', 'hardlink.json', 'hardlink-source.json', 'final-link.json', 'ancestor-link', 'canary.stdout', 'canary.stderr'], 'root_mode': '0700', 'capabilities': 'empty', 'no_new_privileges': True, 'retain_intent_and_result': True}

def store(name, data, mode=0o600):
    fd = os.open(ROOT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def read_output(path, identity):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as output:
        st = os.fstat(output.fileno())
        require((st.st_dev, st.st_ino, st.st_mode) == identity and st.st_uid == 0 and st.st_nlink == 1 and st.st_size <= 512, 'canary output identity or size changed')
        raw = output.read(513)
        require(len(raw) == st.st_size and len(raw) <= 512, 'canary output changed')
        return raw

def apply(reviewed):
    require(plan() == reviewed, 'reviewed plan changed')
    intent_fd = os.open(PARENT_INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(intent_fd, 'wb') as intent:
        intent.write((json.dumps(reviewed, sort_keys=True, separators=(',', ':')) + '\n').encode()); intent.flush(); os.fsync(intent.fileno())
    parent_fd = os.open(ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    ROOT.mkdir(mode=0o700)
    parent_fd = os.open(ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    store('intent.json', (json.dumps(reviewed, sort_keys=True, separators=(',', ':')) + '\n').encode())
    for name in ('valid.json', 'bad-mode.json', 'bad-acl.json', 'hardlink-source.json'): store(name, PUBLIC)
    os.chmod(ROOT / 'bad-mode.json', 0o644, follow_symlinks=False)
    subprocess.run(['/usr/bin/setfacl', '-m', 'u:65534:r--,m::---', str(ROOT / 'bad-acl.json')], env=ENV, check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(stat.S_IMODE((ROOT / 'bad-acl.json').lstat().st_mode) == 0o600, 'ACL fixture must retain private mode')
    os.link(ROOT / 'hardlink-source.json', ROOT / 'hardlink.json', follow_symlinks=False)
    os.symlink('valid.json', ROOT / 'final-link.json')
    os.symlink('.', ROOT / 'ancestor-link')
    store('canary.stdout', b''); store('canary.stderr', b'')
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    paths = [ROOT / name for name in reviewed['files']]
    identities = {str(p): (p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_mode) for p in paths}
    subprocess.run(['/usr/bin/systemd-run', '--quiet', '--unit=sfactory-evidence-reader-canary', '--property=RemainAfterExit=yes', '--property=User=root', '--property=Group=root', '--property=CapabilityBoundingSet=', '--property=AmbientCapabilities=', '--property=NoNewPrivileges=yes', '--property=PrivateNetwork=yes', '--property=MemoryMax=128M', '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=RuntimeMaxSec=30s', '--property=TimeoutStartSec=15s', '--property=StandardOutput=append:'+str(ROOT/'canary.stdout'), '--property=StandardError=append:'+str(ROOT/'canary.stderr'), str(BINARY)], env=ENV, capture_output=True, timeout=10, check=True)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        probe = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', 'SubState', '--value'], env=ENV, capture_output=True, timeout=5, check=True)
        if probe.stdout.strip() == b'exited': break
        if probe.stdout.strip() in (b'failed', b'dead'): raise RuntimeError('canary unit failed')
        time.sleep(0.2)
    else: raise RuntimeError('canary unit outcome unknown')
    require(read_output(ROOT/'canary.stdout', identities[str(ROOT/'canary.stdout')]) == b'PASS: root public evidence positive; wrong digest/mode/ACL/hardlink/final and ancestor symlink refused; no capabilities; no-new-privileges\n' and read_output(ROOT/'canary.stderr', identities[str(ROOT/'canary.stderr')]) == b'', 'canary result mismatch')
    expected = {'LoadState': 'loaded', 'Transient': 'yes', 'Names': 'sfactory-evidence-reader-canary.service', 'FragmentPath': '/run/systemd/transient/sfactory-evidence-reader-canary.service', 'DropInPaths': '', 'User': 'root', 'Group': 'root', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '', 'NoNewPrivileges': 'yes', 'PrivateNetwork': 'yes', 'MemoryMax':'134217728', 'TasksMax':'16', 'CPUQuotaPerSecUSec':'500ms', 'RuntimeMaxUSec':'30s', 'ExecMainCode': '1', 'ExecMainStatus': '0', 'ActiveState': 'active', 'SubState': 'exited', 'Job': ''}
    for key, value in expected.items():
        probe = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', key, '--value'], env=ENV, capture_output=True, timeout=5, check=True)
        require(probe.stdout.decode().strip() == value, 'canary unit property mismatch: ' + key)
    command = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', 'ExecStart', '--value'], env=ENV, capture_output=True, timeout=5, check=True).stdout.decode().strip()
    require(command.startswith('{ path=' + str(BINARY) + ' ; argv[]=' + str(BINARY) + ' ; ignore_errors=no ;') and command.count('{ path=') == 1, 'canary unit command mismatch')
    subprocess.run(['/usr/bin/systemctl', 'stop', 'sfactory-evidence-reader-canary.service'], env=ENV, capture_output=True, timeout=10, check=True)
    for key, value in {'ActiveState':'inactive', 'MainPID':'0', 'Job':''}.items():
        probe = subprocess.run(['/usr/bin/systemctl', 'show', 'sfactory-evidence-reader-canary.service', '-p', key, '--value'], env=ENV, capture_output=True, timeout=5, check=True)
        require(probe.stdout.decode().strip() == value, 'canary stop unverified: '+key)
    # Exact inode/mode revalidation prevents cleanup of substituted entries.
    for path in paths:
        st = path.lstat(); require((st.st_dev, st.st_ino, st.st_mode) == identities[str(path)], 'cleanup identity changed')
    for path in paths: path.unlink()
    store('result.json', b'{"result":"pass","cleanup":"exact-synthetic-files-removed"}\n')
    return {'status': 'pass', 'retained': str(ROOT)}

if __name__ == '__main__':
    if sys.argv == [sys.argv[0], 'plan']:
        reviewed = plan()
        raw = json.dumps(reviewed, sort_keys=True, separators=(',', ':')).encode()
        print(json.dumps({'plan': reviewed, 'sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True))
    elif len(sys.argv) == 3 and sys.argv[1] == 'apply':
        reviewed = plan()
        raw = json.dumps(reviewed, sort_keys=True, separators=(',', ':')).encode()
        require(sys.argv[2] == hashlib.sha256(raw).hexdigest(), 'reviewed plan digest mismatch')
        print(json.dumps(apply(reviewed), sort_keys=True))
    else:
        raise RuntimeError('expected plan or apply with exact plan digest')
