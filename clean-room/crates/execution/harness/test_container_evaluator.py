"""Actual Docker containment proofs; never stress the host filesystem."""

import errno
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from container_evaluator import DockerEvaluator, IMAGE


@unittest.skipUnless(shutil.which("docker"), "Docker required")
class ContainerEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            subprocess.run(
                ["docker", "image", "inspect", IMAGE],
                capture_output=True,
                check=True,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            raise unittest.SkipTest("pinned cached image and Docker required")

    def evaluate(self, source, fixtures=None, requests=({},)):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "solution.py").write_text(source)
            result = DockerEvaluator(path, path / "evidence")(
                requests,
                fixtures
                or dict(files={}, directories=("scratch",), symlinks={}, pin_files=()),
            )
            self.assertTrue(result["sandbox_verified"], result)
            self.assertTrue(result["cleanup_verified"], result)
            return result

    def test_atomic_replace_preserves_original_fd(self):
        result = self.evaluate(
            """import os,json
open('scratch/new','wb').write(b'new')
os.replace('scratch/new','scratch/config')
print(json.dumps({'result': 'ok'}))
""",
            dict(
                files={"scratch/config": b"old"},
                directories=("scratch",),
                symlinks={},
                pin_files=("scratch/config",),
            ),
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["files"], {"scratch/config": b"new"})
        self.assertEqual(result["original_fd_bytes"], {"scratch/config": b"old"})

    def test_json_lines_interval(self):
        result = self.evaluate(
            """import sys,json
for line in sys.stdin:
 r=json.loads(line); print(json.dumps({'result':r['value']+1}))
""",
            requests=({"value": 1}, {"value": 8}),
        )
        self.assertEqual(
            [json.loads(line) for line in result["stdout"].splitlines()],
            [{"result": 2}, {"result": 9}],
        )

    def test_host_oracle_network_parent_fd_and_fork_denied(self):
        result = self.evaluate("""import os,socket,json
out={}
for label,path in [('host','/Users/bo/code/software-factory-goose/AGENTS.md'),('oracle','/work/benchmark_acceptance.py'),('parent','/proc/1/fd/1'),('source','/work/solution.py')]:
 try:
  with open(path,'wb' if label in ('parent','source') else 'rb') as f: f.write(b'forged') if label in ('parent','source') else f.read()
  out[label]='allowed'
 except OSError: out[label]='denied'
try: os.fork();out['fork']='allowed'
except OSError as e: out['fork']=e.errno
try: socket.create_connection(('1.1.1.1',53),.2);out['network']='allowed'
except OSError: out['network']='denied'
out['uid']=os.getuid()
out['caps']=[l.strip() for l in open('/proc/self/status') if l.startswith('CapEff:')][0]
print(json.dumps(out))
""")
        self.assertEqual(result["exit_code"], 0)
        report = json.loads(result["stdout"])
        self.assertEqual(
            {
                key: report[key]
                for key in ("host", "oracle", "parent", "source", "network")
            },
            dict.fromkeys(("host", "oracle", "parent", "source", "network"), "denied"),
        )
        self.assertEqual(report["fork"], errno.EPERM)
        self.assertEqual(report["uid"], 1001)
        self.assertEqual(report["caps"].split()[-1], "0000000000000000")

    def test_aggregate_scratch_bytes_enospc(self):
        result = self.evaluate("""import errno,json
written=0
try:
 for i in range(40):
  with open('scratch/f'+str(i),'wb') as f:
   f.write(b'x'*32768); written+=32768
except OSError as e: print(json.dumps({'errno':e.errno,'written':written}))
""")
        report = json.loads(result["stdout"])
        self.assertEqual(report["errno"], errno.ENOSPC)
        self.assertLessEqual(report["written"], 1048576)
        self.assertTrue(
            result["overflow"]
        )  # Evidence cap fails closed, never silently accepts partial state.

    def test_inode_limit_enospc(self):
        result = self.evaluate("""import json
try:
 for i in range(200): open('scratch/f'+str(i),'xb').close()
except OSError as e: print(json.dumps({'errno':e.errno,'count':i}))
""")
        report = json.loads(result["stdout"])
        self.assertEqual(report["errno"], errno.ENOSPC)
        self.assertLess(report["count"], 128)
        self.assertFalse(result["overflow"])

    def test_live_aggregate_limits(self):
        result = self.evaluate("""import os,json
report={name:open('/sys/fs/cgroup/'+name).read().strip() for name in ['memory.max','memory.swap.max','pids.max','cpu.max']}
report['scratch_bytes']=os.statvfs('/work/scratch').f_blocks*os.statvfs('/work/scratch').f_frsize
report['scratch_inodes']=os.statvfs('/work/scratch').f_files
print(json.dumps(report))
""")
        report = json.loads(result["stdout"])
        self.assertEqual(report["memory.max"], "134217728")
        self.assertEqual(report["memory.swap.max"], "0")
        self.assertEqual(report["pids.max"], "16")
        quota, period = map(int, report["cpu.max"].split())
        self.assertEqual(quota, period)
        self.assertEqual(report["scratch_bytes"], 1048576)
        self.assertEqual(report["scratch_inodes"], 128)

    def test_output_and_wall_deadlines(self):
        result = self.evaluate("import os\nwhile True: os.write(1,b'x'*4096)\n")
        self.assertTrue(result["overflow"])
        result = self.evaluate("import time\ntime.sleep(20)\n")
        self.assertTrue(result["timed_out"])

    def test_symlinks_and_invalid_fixture(self):
        result = self.evaluate(
            "pass",
            dict(
                files={"scratch/file": b"x"},
                directories=("scratch",),
                symlinks={"scratch/link": "file"},
                pin_files=(),
            ),
        )
        self.assertEqual(result["symlinks"], {"scratch/link": "file"})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "solution.py").write_text('raise Exception("must not execute")')
            result = DockerEvaluator(path, path / "e")(
                ({},),
                dict(
                    files={},
                    directories=("scratch",),
                    symlinks={"scratch/x": "../../escape"},
                    pin_files=(),
                ),
            )
            self.assertFalse(result["sandbox_verified"])
            self.assertEqual(result["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
