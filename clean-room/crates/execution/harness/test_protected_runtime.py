"""Real workspace and containment boundaries, without provider credentials."""

import json
from pathlib import Path
import tempfile
import unittest
import threading
import time
import platform
import os
from unittest.mock import patch
from types import SimpleNamespace

from factory_harness import Denied
from protected_goose_runtime import (
    BoundedWorkspace,
    DockerEvaluator,
    ModelRelay,
    parse_completion,
    run_bounded,
    profile_fingerprints,
    ProtectedGooseAdapter,
)


class ProtectedRuntime(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("SFACTORY_TEST_GOOSE"), "actual pinned native artifacts"
    )
    def test_setup_failure_closes_resources_and_revokes_even_when_cleanup_raises(self):
        class Control:
            config = {"model": "auto", "route_sha256": "a" * 64}
            revoked = False

            def revoke(self, attempt):
                self.revoked = True

        with tempfile.TemporaryDirectory() as directory:
            suite = json.loads(
                Path(__file__).with_name("frozen-suite.json").read_text()
            )
            control = Control()
            adapter = ProtectedGooseAdapter(
                Path(directory) / "runtime",
                suite,
                goose=os.environ["SFACTORY_TEST_GOOSE"],
                host=os.environ["SFACTORY_TEST_SCRIPT_HOST"],
                normalizer=os.environ["SFACTORY_TEST_NORMALIZER"],
                control=control,
            )
            attempt = {
                "attempt_id": "run_" + "b" * 64,
                "task_id": "atomic-config",
                "variant": "baseline",
                "model": "auto",
                "profile": adapter.profiles["baseline"],
                "goose_build": "c" * 64,
                "route": "a" * 64,
            }
            original_write = Path.write_text
            original_close = BoundedWorkspace.close

            def fail_profile(path, *args, **kwargs):
                if path.name == "worker.sb":
                    raise OSError("injected setup failure")
                return original_write(path, *args, **kwargs)

            def fail_close(workspace):
                original_close(workspace)
                raise OSError("injected cleanup failure")

            with (
                patch.object(Path, "write_text", fail_profile),
                patch.object(BoundedWorkspace, "close", fail_close),
            ):
                with self.assertRaises(OSError):
                    adapter.generate(attempt, {"status": "allowed"})
            self.assertTrue(control.revoked)

    def test_profile_fingerprint_tracks_code_contract_binaries_and_route(self):
        with tempfile.TemporaryDirectory() as directory:
            files = [Path(directory) / name for name in ("goose", "host", "normalizer")]
            for f in files:
                f.write_bytes(b"fixture-binary")
            first = profile_fingerprints(*files, model="auto", route="a" * 64)
            self.assertNotEqual(first["baseline"], first["candidate"])
            self.assertEqual(
                first, profile_fingerprints(*files, model="auto", route="a" * 64)
            )
            files[1].write_bytes(b"changed-host")
            self.assertNotEqual(
                first, profile_fingerprints(*files, model="auto", route="a" * 64)
            )
            self.assertNotEqual(
                first, profile_fingerprints(*files, model="auto", route="b" * 64)
            )

    def test_stream_terminal_state_and_metadata_cannot_hide_unmasked_text(self):
        first = {
            "id": "secret",
            "model": "auto",
            "choices": [
                {"index": 0, "delta": {"content": "done"}, "finish_reason": "stop"}
            ],
        }

        def encode(events):
            return (
                "".join("data: " + json.dumps(e) + "\n\n" for e in events)
                + "data: [DONE]\n\n"
            ).encode()

        safe, _, _ = parse_completion(
            encode([first]), lambda s: s.replace("secret", "MASKED"), {"auto"}, set()
        )
        with self.subTest("metadata normalization"):
            self.assertNotIn(b"secret", safe)
        late = {
            "id": "secret",
            "model": "auto",
            "choices": [
                {"index": 0, "delta": {"content": "late"}, "finish_reason": None}
            ],
        }
        with self.subTest("terminal state"), self.assertRaises(Denied):
            parse_completion(encode([first, late]), lambda s: s, {"auto"}, set())
        unsafe_usage = first | {"usage": {"prompt_tokens": 2, "debug": "secret"}}
        with self.subTest("unsupported metadata"), self.assertRaises(Denied):
            parse_completion(encode([unsafe_usage]), lambda s: s, {"auto"}, set())

    @unittest.skipUnless(platform.system() == "Darwin", "native Seatbelt boundary")
    def test_evaluator_cannot_read_oracles_siblings_network_or_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            work = root / "work"
            work.mkdir()
            private = root / "private.txt"
            private.write_text("controller-only")
            oracle = Path(__file__).with_name("benchmark_acceptance.py").resolve()
            (work / "solution.py").write_text(
                "import errno,json,os,socket\nresults=[]\n"
                + "for path in "
                + repr(
                    [str(private), str(oracle), "/System/Volumes/Data" + str(private)]
                )
                + ":\n"
                + " try:open(path).read();results.append(False)\n except OSError:results.append(True)\n"
                + 's=socket.socket();s.settimeout(.2);results.append(s.connect_ex(("198.51.100.1",443)) in (errno.EPERM,errno.EACCES,errno.ENETUNREACH))\n'
                + "try:\n pid=os.fork()\n if pid==0:os._exit(0)\n os.waitpid(pid,0);results.append(False)\nexcept PermissionError:results.append(True)\n"
                + 'print(json.dumps({"result":results}))\n'
            )
            result = DockerEvaluator(work, root / "eval")(
                ({},),
                {
                    "files": {},
                    "directories": ("scratch",),
                    "symlinks": {},
                    "pin_files": (),
                },
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(json.loads(result["stdout"]), {"result": [True] * 5})
            self.assertTrue(result["sandbox_verified"])

    def test_process_capture_has_explicit_overflow_and_timeout_without_partial_success(
        self,
    ):
        result = run_bounded(
            ["/usr/bin/python3", "-c", "print('x'*1100000)"], cwd="/", env={}, timeout=5
        )
        self.assertTrue(result["overflow"])
        self.assertEqual(result["stdout"], b"")
        result = run_bounded(["/bin/sleep", "2"], cwd="/", env={}, timeout=0.05)
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)

    def test_equivalent_goose_argument_serialization_preserves_exact_transcript_authority(
        self,
    ):
        class Control:
            calls = 0

            def exchange(self, attempt, body, sequence):
                self.calls += 1
                if sequence == 0:
                    delta = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "t1",
                                "type": "function",
                                "function": {
                                    "name": "factory__write_file",
                                    "arguments": '{"path": "x.py", "content": "hello"}',
                                },
                            }
                        ],
                    }
                    finish = "tool_calls"
                else:
                    delta, finish = {"content": "done"}, "stop"
                events = [
                    {
                        "model": "auto",
                        "choices": [
                            {"index": 0, "delta": delta, "finish_reason": None}
                        ],
                    },
                    {
                        "model": "auto",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                    },
                ]
                return {
                    "sse": (
                        "".join("data: " + json.dumps(e) + "\n\n" for e in events)
                        + "data: [DONE]\n\n"
                    ).encode(),
                    "call_id": f"call-{sequence}",
                    "physical_manifest_sha256": "a" * 64,
                    "billing_receipt_sha256": "b" * 64,
                }

        session = SimpleNamespace(
            cancelled=threading.Event(),
            declarations=lambda: [{"name": "write_file"}],
            call=lambda *args: {"status": "executed", "output": "done"},
        )
        control = Control()
        relay = ModelRelay(
            {
                "goose_build": "a" * 64,
                "profile": "b" * 64,
                "route": "c" * 64,
                "model": "auto",
            },
            session,
            control,
            "task",
            "unused",
            lambda s: s,
            time.monotonic() + 5,
        )
        initial = {
            "model": "auto",
            "stream": True,
            "max_tokens": 100,
            "tools": [{"function": {"name": "factory__write_file"}}],
            "messages": [
                {"role": "system", "content": "fixed"},
                {"role": "user", "content": "task"},
            ],
        }
        relay.exchange(initial)
        result = relay.tool("write_file", {"path": "x.py", "content": "hello"})
        assistant = json.loads(json.dumps(relay.assistant))
        assistant.pop("content")
        assistant["tool_calls"][0]["function"]["arguments"] = (
            '{"content":"hello","path":"x.py"}'
        )
        continuation = initial | {
            "messages": initial["messages"]
            + [
                assistant,
                {"role": "tool", "tool_call_id": "t1", "content": json.dumps(result)},
            ]
        }
        relay.exchange(continuation)
        self.assertEqual(control.calls, 2)
        with self.assertRaises(Denied):
            relay.exchange(initial)
        self.assertEqual(control.calls, 2)

    def test_total_workspace_limit_refuses_before_persisting_excess_file(self):
        with tempfile.TemporaryDirectory() as directory:
            ws = BoundedWorkspace(Path(directory), lambda s: s)
            try:
                for index in range(32):
                    ws.write({"path": f"file-{index}.txt", "content": "x" * 32768})
                with self.assertRaises(Denied):
                    ws.write({"path": "excess.txt", "content": "x"})
                self.assertFalse((Path(directory) / "excess.txt").exists())
            finally:
                ws.close()

    def test_mask_logical_text_after_all_sse_fragments_are_assembled(self):
        events = [
            {
                "model": "auto",
                "choices": [
                    {"index": 0, "delta": {"content": "split-"}, "finish_reason": None}
                ],
            },
            {
                "model": "auto",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": "secret"},
                        "finish_reason": "stop",
                    }
                ],
            },
        ]
        raw = (
            "".join("data: " + json.dumps(e) + "\n\n" for e in events)
            + "data: [DONE]\n\n"
        ).encode()
        safe, assistant, _ = parse_completion(
            raw, lambda s: s.replace("split-secret", "MASKED"), {"auto"}, set()
        )
        self.assertEqual(assistant["content"], "MASKED")
        self.assertNotIn(b"split-secret", safe)

    def test_typed_workspace_never_follows_links_or_accepts_authority_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            work.mkdir()
            outside = root / "outside"
            outside.write_text("private")
            ws = BoundedWorkspace(work, lambda s: s.replace("private", "[REDACTED]"))
            ws.write({"path": "solution.py", "content": "private"})
            self.assertEqual(ws.read({"path": "solution.py"}), "[REDACTED]")
            (work / "link").symlink_to(outside)
            for args in (
                {"path": "../outside"},
                {"path": "/outside"},
                {"path": "link"},
                {"path": ".git/config"},
                {"path": "solution.py", "workdir": "/"},
            ):
                with self.subTest(args=args), self.assertRaises(Denied):
                    ws.read(args)
            self.assertEqual(outside.read_text(), "private")
            ws.close()

    def test_complete_stream_normalized_before_assistant_and_no_partial_tool_call(self):
        chunks = [
            {
                "model": "auto",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "t1",
                                    "type": "function",
                                    "function": {
                                        "name": "factory__write_file",
                                        "arguments": '{"path":"solution.py","content":"secret"}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": None,
                    }
                ],
            },
            {
                "model": "auto",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
            },
        ]
        raw = (
            "".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
            + "data: [DONE]\n\n"
        ).encode()
        normalized, assistant, ids = parse_completion(
            raw,
            lambda s: s.replace("secret", "MASKED"),
            {"auto"},
            {"factory__write_file"},
        )
        self.assertNotIn(b"secret", normalized)
        self.assertIn("MASKED", assistant["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(ids, ["t1"])
        with self.assertRaises(Denied):
            parse_completion(
                raw.replace(b"data: [DONE]\n\n", b""),
                lambda s: s,
                {"auto"},
                {"factory__write_file"},
            )
        with self.assertRaises(Denied):
            parse_completion(raw, lambda s: s, {"wrong"}, {"factory__write_file"})


if __name__ == "__main__":
    unittest.main()
