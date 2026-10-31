"""Acceptance oracle tests; subprocess doubles do not certify an OS sandbox."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from benchmark_acceptance import cases, contract, evaluate, fixtures, task_ids


def response(stdout, **changes):
    return (
        dict(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            timed_out=False,
            overflow=False,
            sandbox_verified=True,
            cleanup_verified=True,
            files={},
            original_fd_bytes={},
            symlinks={},
        )
        | changes
    )


class Acceptance(unittest.TestCase):
    def test_every_frozen_task_has_public_contract_and_distinguishing_oracles(self):
        frozen = json.loads((Path(__file__).parent / "frozen-suite.json").read_text())
        self.assertEqual(set(task_ids()), {v["id"] for v in frozen["tasks"]})
        for name in task_ids():
            with self.subTest(task=name):
                self.assertIn("solution.py", contract(name))
                self.assertGreaterEqual(len(cases(name)), 3)
                seen = []

                def wrong(requests, setup):
                    seen.append((requests, setup))
                    self.assertTrue(all("expected" not in r for r in requests))
                    return response(b'{"result":null}\n' * len(requests))

                result = evaluate(name, "a" * 64, wrong)
                self.assertFalse(result["accepted"])
                self.assertTrue(result["independent"])
                self.assertEqual(len(seen), 1)

    def test_exit_status_partial_output_forged_safety_and_duplicate_json_rejected(self):
        good = b'{"result":[[1,5],[8,9]]}\n{"result":[]}\n{"error":"invalid"}\n'
        for changes in (
            {"exit_code": 1},
            {"stdout": good.splitlines()[0] + b"\n"},
            {"stdout": good + b'{"result":0}\n'},
            {"timed_out": True},
            {"overflow": True},
            {"sandbox_verified": False},
            {"cleanup_verified": False},
            {
                "stdout": b'{"result":"WRONG","result":[[1,5],[8,9]]}\n{"result":[]}\n{"error":"invalid"}\n'
            },
        ):
            with self.subTest(changes=changes):
                out = evaluate(
                    "intervals", "a" * 64, lambda *args: response(good) | changes
                )
                self.assertFalse(out["accepted"])
        self.assertTrue(
            evaluate("intervals", "a" * 64, lambda *args: response(good))["accepted"]
        )

    def test_real_black_box_program_for_four_independent_interfaces(self):
        program = """import json,sys,urllib.parse
def solve(v):
 if "intervals" in v:
  xs=sorted(v["intervals"]); out=[]
  for a,b in xs:
   if type(a)!=int or type(b)!=int or a>b:raise ValueError()
   if out and a<=out[-1][1]:out[-1][1]=max(out[-1][1],b)
   else:out.append([a,b])
  return out
 if "matrix" in v:
  m=v["matrix"]
  if m and any(len(row)!=len(m[0]) for row in m):raise ValueError()
  return [list(row) for row in zip(*(m[::-1] if v["op"]=="rotate" else m))]
 if "pairs" in v:return urllib.parse.urlencode([tuple(p) for p in v["pairs"]])
 if "query" in v:return [list(p) for p in urllib.parse.parse_qsl(v["query"],keep_blank_values=True)]
 if "base" in v:
  if any(type(v[k])!=int or v[k]<0 for k in ("base","attempts","max_delay")):raise ValueError()
  return [min(v["base"]*2**i,v["max_delay"]) for i in range(v["attempts"])]
 raise ValueError()
for line in sys.stdin:
 try:print(json.dumps({"result":solve(json.loads(line))},ensure_ascii=False))
 except Exception:print(json.dumps({"error":"invalid"}))
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "solution.py"
            path.write_text(program)

            def executor(requests, setup):
                p = subprocess.run(
                    [sys.executable, "-I", "-B", str(path)],
                    input=b"".join(json.dumps(v).encode() + b"\n" for v in requests),
                    capture_output=True,
                    timeout=5,
                    env={},
                    cwd=tmp,
                )
                return response(p.stdout, exit_code=p.returncode, stderr=p.stderr)

            for name in (
                "intervals",
                "matrix-transform",
                "query-encoding",
                "retry-schedule",
            ):
                with self.subTest(task=name):
                    self.assertTrue(evaluate(name, "a" * 64, executor)["accepted"])

    def test_file_mutations_cannot_self_report_success(self):
        setup = fixtures("atomic-config")
        good = b'{"result":{"x":2}}\n{"error":"invalid"}\n{"error":"invalid"}\n'
        # An in-place writer corrupts the pinned original descriptor even if the
        # candidate emits the right JSON and leaves the right final target bytes.
        files = dict(setup["files"])
        files["scratch/config-0.json"] = b'{"x":2}'
        pinned = dict(setup["files"])
        okay = response(good, files=files, original_fd_bytes=pinned)
        self.assertTrue(
            evaluate("atomic-config", "a" * 64, lambda *args: okay)["accepted"]
        )
        corrupt = dict(pinned, **{"scratch/config-0.json": b'{"x":2}'})
        self.assertFalse(
            evaluate(
                "atomic-config",
                "a" * 64,
                lambda *args: okay | {"original_fd_bytes": corrupt},
            )["accepted"]
        )
        self.assertFalse(
            evaluate(
                "atomic-config",
                "a" * 64,
                lambda *args: okay | {"files": setup["files"]},
            )["accepted"]
        )

    def test_real_file_cli_with_parent_collected_snapshots_and_pinned_descriptors(self):
        program = """import hashlib,json,os,pathlib,sys,tempfile
def solve(v):
 if "replacement" in v:
  replacement=v["replacement"]
  if not isinstance(replacement,dict) or any(type(n)!=int or n<0 for n in replacement.values()):raise ValueError()
  path=pathlib.Path(v["path"])
  fd,tmp=tempfile.mkstemp(dir=path.parent)
  with os.fdopen(fd,"w") as f:json.dump(replacement,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
  return replacement
 base=pathlib.Path(v["directory"])
 if not base.is_dir():raise ValueError()
 result={}
 for root,dirs,files in os.walk(base,followlinks=False):
  dirs[:]=[d for d in dirs if not pathlib.Path(root,d).is_symlink()]
  for name in files:
   path=pathlib.Path(root,name)
   if path.is_file() and not path.is_symlink():result[path.relative_to(base).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
 return dict(sorted(result.items()))
for line in sys.stdin:
 try:print(json.dumps({"result":solve(json.loads(line))}))
 except Exception:print(json.dumps({"error":"invalid"}))
"""

        def executor(requests, setup):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "solution.py"
                path.write_text(program)
                for name in setup["directories"]:
                    (root / name).mkdir(parents=True, exist_ok=True)
                for name, value in setup["files"].items():
                    (root / name).parent.mkdir(parents=True, exist_ok=True)
                    (root / name).write_bytes(value)
                for name, target in setup["symlinks"].items():
                    (root / name).symlink_to(target)
                pins = {
                    name: os.open(root / name, os.O_RDONLY)
                    for name in setup["pin_files"]
                }
                try:
                    p = subprocess.run(
                        [sys.executable, "-I", "-B", str(path)],
                        input=b"".join(
                            json.dumps(v).encode() + b"\n" for v in requests
                        ),
                        capture_output=True,
                        timeout=5,
                        env={},
                        cwd=tmp,
                    )
                    files, links = {}, {}
                    for item in (root / "scratch").rglob("*"):
                        name = item.relative_to(root).as_posix()
                        if item.is_symlink():
                            links[name] = os.readlink(item)
                        elif item.is_file():
                            files[name] = item.read_bytes()
                    return response(
                        p.stdout,
                        exit_code=p.returncode,
                        stderr=p.stderr,
                        files=files,
                        symlinks=links,
                        original_fd_bytes={
                            name: os.pread(fd, 65536, 0) for name, fd in pins.items()
                        },
                    )
                finally:
                    for fd in pins.values():
                        os.close(fd)

        for name in ("atomic-config", "file-manifest"):
            with self.subTest(task=name):
                self.assertTrue(evaluate(name, "a" * 64, executor)["accepted"])

    def test_metadata_is_bound_and_errors_never_include_candidate_streams(self):
        result = evaluate(
            "intervals",
            "a" * 64,
            lambda *args: (_ for _ in ()).throw(
                RuntimeError("secret-from-private-executor")
            ),
        )
        self.assertFalse(result["accepted"])
        self.assertFalse(result["safety_passed"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["artifact_sha256"], "a" * 64)
        self.assertEqual(len(result["evaluator_build"]), 64)
        self.assertEqual(len(result["evaluation_receipt_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
