#!/usr/bin/env python3
"""Protected temporary Unix-to-fixed-loopback relay for synthetic backend integration only."""
import os
import json
import shutil
import pathlib
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def verify_promotion_decision(ingress_port, env, checkpoint, mode):
    if not isinstance(ingress_port, int) or not 0 < ingress_port < 65536 or mode not in ('exercise', 'verify'):
        raise ValueError('explicit fixture ingress and mode required')
    subprocess.run([str(ROOT / 'target/debug/examples/promotion_decision_fixture'), str(ingress_port), mode, checkpoint], cwd=ROOT, env=env, check=True, timeout=90)


def verify_worker_backend(ingress_port, env):
    if not isinstance(ingress_port, int) or not 0 < ingress_port < 65536:
        raise ValueError('explicit fixture ingress port required')
    slots = threading.BoundedSemaphore(8)
    lost_reply = threading.Event()
    fault_lock = threading.Lock()

    class Relay(socketserver.BaseRequestHandler):
        discard_one_response = False
        def handle(self):
            if not slots.acquire(blocking=False):
                return
            try:
                with socket.create_connection(('127.0.0.1', ingress_port), timeout=5) as upstream:
                    self.request.settimeout(5)
                    upstream.settimeout(5)
                    peers = {self.request: upstream, upstream: self.request}
                    deadline = time.monotonic() + 20
                    total = 0
                    request_forwarded = False
                    while peers and time.monotonic() < deadline:
                        ready, _, _ = select.select(list(peers), [], [], min(1, max(0, deadline - time.monotonic())))
                        for source in ready:
                            data = source.recv(16384)
                            if not data:
                                peers[source].shutdown(socket.SHUT_WR)
                                del peers[source]
                                continue
                            total += len(data)
                            if total > 1024 * 1024:
                                return
                            if source is self.request:
                                request_forwarded = True
                            if source is upstream and request_forwarded and self.discard_one_response:
                                with fault_lock:
                                    if not lost_reply.is_set():
                                        # The dedicated fault socket is used only for a
                                        # synthetic consume. Forward no acknowledgement.
                                        lost_reply.set()
                                        return
                            peers[source].sendall(data)
            except (OSError, TimeoutError):
                # No request bodies, credentials or SDK output enter fixture diagnostics.
                return
            finally:
                slots.release()

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = False

    class LostReplyRelay(Relay):
        discard_one_response = True

    # Workspace ancestors satisfy the backend's protected-path checks; /tmp does not.
    with tempfile.TemporaryDirectory(prefix='.worker-fixture-', dir=ROOT) as directory:
        os.chmod(directory, 0o700)
        path = str(pathlib.Path(directory) / 'ingress.sock')
        lost_path = str(pathlib.Path(directory) / 'lost.sock')
        if len(os.fsencode(path)) >= 104:
            raise ValueError('fixture Unix socket path too long')
        with Server(path, Relay) as server, Server(lost_path, LostReplyRelay) as lossy:
            os.chmod(path, 0o600)
            os.chmod(lost_path, 0o600)
            started = []
            try:
                for current in (server, lossy):
                    thread = threading.Thread(target=current.serve_forever, kwargs={'poll_interval': 0.1})
                    thread.start()
                    started.append((current, thread))
                subprocess.run([str(ROOT / 'target/debug/examples/worker_backend_fixture'), path, str(ingress_port)], cwd=ROOT, env=env, check=True, timeout=90)
                subprocess.run([str(ROOT / 'target/debug/examples/operator_backend_fixture'), path, lost_path], cwd=ROOT, env=env, check=True, timeout=90)
                if not lost_reply.is_set():
                    raise RuntimeError('operator fixture did not exercise reply-loss injection')
                lost_reply.clear()
                subprocess.run([str(ROOT / 'target/debug/examples/intake_backend_fixture'), path, lost_path], cwd=ROOT, env=env, check=True, timeout=90)
                if not lost_reply.is_set():
                    raise RuntimeError('intake fixture did not exercise reply-loss injection')
            finally:
                for current, thread in started:
                    current.shutdown()
                for current, thread in started:
                    thread.join(timeout=5)
                if any(thread.is_alive() for _, thread in started):
                    raise RuntimeError('fixture relay did not stop')


def prepare_promotion_execution(home, env):
    """Create only owned disposable repositories, never clone/link a user checkout."""
    root = pathlib.Path(home).resolve() / 'promotion-execution'
    root.mkdir(mode=0o700)
    candidate = root / 'candidate'
    candidate.mkdir(mode=0o700)
    git_env = {'PATH':'/usr/bin:/bin', 'HOME':str(root), 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null'}
    def git(path, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(path), *args], env=git_env, stderr=subprocess.DEVNULL, text=True, timeout=10).strip()
    git(candidate, 'init', '-b', 'main')
    git(candidate, 'config', 'user.name', 'Fixture')
    git(candidate, 'config', 'user.email', 'fixture@example.invalid')
    (candidate / 'README').write_text('base\n')
    git(candidate, 'add', 'README'); git(candidate, 'commit', '-m', 'base')
    base = git(candidate, 'rev-parse', 'HEAD')
    (candidate / 'README').write_text('candidate\n')
    git(candidate, 'add', 'README'); git(candidate, 'commit', '-m', 'candidate')
    sha = git(candidate, 'rev-parse', 'HEAD')
    for name in ('target.git', 'refusal.git'):
        target = root / name
        target.mkdir(mode=0o700)
        git(target, 'init', '--bare')
        git(target, 'config', 'core.logallrefupdates', 'true')
        shutil.copytree(candidate / '.git/objects', target / 'objects', dirs_exist_ok=True)
        git(target, 'update-ref', 'refs/heads/main', base)
    env['SFACTORY_FIXTURE_PROMOTION_ROOT'] = str(root)
    return {'root':root, 'base':base, 'sha':sha, 'git':git}


def verify_promotion_execution(ingress, fixture, post, checkpoint=None):
    """Synthetic source publishes evidence; this proves journal/Git contracts, not auth."""
    if not isinstance(ingress, int) or not 0 < ingress < 65536:
        raise ValueError('explicit loopback fixture port required')
    root, base, sha, git = (fixture[key] for key in ('root','base','sha','git'))
    prefix = f'http://127.0.0.1:{ingress}/restate/call/PromotionDecisionJournal/'
    if checkpoint is None:
        def decided(task, repository):
            url = prefix + task
            action = {'operation':{'type':'promote'},'task_id':task,'repository':repository,'target_ref':'refs/heads/main','candidate_sha':sha,'base_sha':base,'evidence_digest':'c'*64,'reason':'authoritative eligibility publication','audience':'fixture'}
            assert post(url+'/publish',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','expected_generation':0,'action':action})[0] == 200
            code, approval = post(url+'/issue',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','reason':'synthetic exact Git action','ttl_ms':300000})
            assert code == 200, code
            record = approval['record']
            assert post(url+'/execute',record['nonce'])[0] == 409
            presentation = {key:record[key] for key in ('action','nonce','issued_at_ms','expires_at_ms')}
            assert post(url+'/consume',presentation)[0] == 200
            return record['nonce']
        nonce = decided('execution-fixture','fixture-execution')
        path = '/restate/call/PromotionDecisionJournal/execution-fixture/execute'
        encoded = json.dumps(nonce).encode()
        with socket.create_connection(('127.0.0.1',ingress),timeout=10) as wire:
            wire.sendall(b'POST '+path.encode()+b' HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
            assert wire.recv(1) == b'H'  # response began; deliberately discard its receipt.
        code, summary = post(prefix+'execution-fixture/inspect',None)
        assert code == 200, code
        completed = summary['current_decision']['execution']['Completed']
        receipt = completed['receipt']
        assert receipt['disposition'] == 'Advanced' and receipt['attribution_unknown'] is False
        assert git(root/'target.git','rev-parse','refs/heads/main') == sha
        reflog = git(root/'target.git','reflog','show','--format=%H','refs/heads/main')
        assert post(prefix+'execution-fixture/execute',nonce) == (200,receipt)
        assert post(prefix+'execution-fixture/execute',{'nonce':nonce,'path':str(root/'refusal.git')})[0] == 400
        rejected = decided('execution-refusal-fixture','fixture-refusal')
        (root/'candidate/README').write_text('dirty fixture\n')
        assert post(prefix+'execution-refusal-fixture/execute',rejected)[0] == 409
        code, refused = post(prefix+'execution-refusal-fixture/inspect',None)
        assert code == 200 and 'Prepared' in refused['current_decision']['execution']
        (root/'candidate/README').write_text('candidate\n')
        # The first attempt already recorded intent. Restoring a clean snapshot must NOT
        # turn retry into a second fresh CAS, even though the target still equals base.
        assert post(prefix+'execution-refusal-fixture/execute',rejected)[0] == 409
        assert git(root/'refusal.git','rev-parse','refs/heads/main') == base
        fresh_action = {**refused['current_decision']['action'], 'reason':'authoritative eligibility publication'}
        republish = {'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAZ','expected_generation':1,'action':fresh_action}
        assert post(prefix+'execution-refusal-fixture/publish',republish)[0] == 409
        assert post(prefix+'execution-refusal-fixture/invalidate',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAY','expected_generation':1})[0] == 200
        assert post(prefix+'execution-refusal-fixture/execute',rejected)[0] == 409
        republish['expected_generation'] = 2
        assert post(prefix+'execution-refusal-fixture/publish',republish)[0] == 409
        assert post(prefix+'execution-refusal-fixture/issue',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FB0','reason':'retry unresolved action','ttl_ms':300000})[0] == 409
        checkpoint = {'nonce':nonce,'receipt':receipt,'reflog':reflog,'rejected':rejected,'republish':republish}
        print('PASS: durable exact Git CAS, discarded reply, server-resolved action and Prepared retry/invalidation refusal')
    else:
        assert post(prefix+'execution-fixture/execute',checkpoint['nonce']) == (200,checkpoint['receipt'])
        assert post(prefix+'execution-refusal-fixture/execute',checkpoint['rejected'])[0] == 409
        assert post(prefix+'execution-refusal-fixture/publish',checkpoint['republish'])[0] == 409
        assert git(root/'target.git','rev-parse','refs/heads/main') == sha
        assert git(root/'target.git','reflog','show','--format=%H','refs/heads/main') == checkpoint['reflog']
        assert git(root/'refusal.git','rev-parse','refs/heads/main') == base
        print('PASS: exact promotion receipt and invalidated Prepared refusal survived Restate SIGKILL without a second ref write')
    return checkpoint
