"""Opt-in Goose/MCP candidate interface; not registered in any live launcher.

A trusted adapter constructs this session using existing bounded tool transports,
atomic spending authority, protected worktree snapshots and the Rust normalizer.
"""

from pathlib import Path
import time
import threading
from factory_harness import ArtifactStore, Denied, MAX_OUTPUT, StallDetector, run_script
from harness_evaluation import observation

SCRIPT_SCHEMA = {
    "type": "object",
    "properties": {"script": {"type": "string", "maxLength": 32768}},
    "required": ["script"],
    "additionalProperties": False,
}
DISCOVERY_SCHEMA = {
    "type": "object",
    "properties": {"name": {"type": "string"}},
    "required": ["name"],
    "additionalProperties": False,
}


class CandidateSession:
    def __init__(
        self, *, host, broker, artifact_root, attempt, snapshot, deadline, cancelled
    ):
        self.host, self.broker = Path(host), broker
        self.profile = broker.profile
        self.artifacts = ArtifactStore(artifact_root, attempt, broker.normalize)
        self.attempt, self.snapshot = attempt, snapshot
        self.deadline, self.cancelled = deadline, cancelled
        self.stalls = StallDetector()
        self.receipts = []
        self.lock = threading.Lock()

    def declarations(self):
        return [
            {
                "name": "run_script",
                "description": "Use await tools.call(name, arguments), await tools.readBatch([{name, arguments}]), or await tools.fetchToolSchema(name). Log or return a concise result. Await mutations in order.",
                "inputSchema": SCRIPT_SCHEMA,
            },
            {
                "name": "fetch_tool_schema",
                "description": "Discover a tool schema; discovery never grants permission.",
                "inputSchema": DISCOVERY_SCHEMA,
            },
        ]

    def call(self, name, arguments):
        if not self.lock.acquire(blocking=False):
            return {"status": "refused", "reason": "busy"}
        try:
            return self._call(name, arguments)
        except Exception:
            return {"status": "refused", "reason": "execution_unavailable"}
        finally:
            self.lock.release()

    def _call(self, name, arguments):
        if self.cancelled.is_set() or time.monotonic() >= self.deadline:
            return {"status": "refused", "reason": "attempt_closed"}
        if not isinstance(arguments, dict):
            return {"status": "refused", "reason": "invalid_request"}
        if name == "fetch_tool_schema" and set(arguments) == {"name"}:
            try:
                return {
                    "status": "executed",
                    "schema": self.profile.discover(arguments["name"]),
                }
            except (Denied, TypeError):
                return {"status": "refused", "reason": "unknown_tool"}
        if name != "run_script" or set(arguments) != {"script"}:
            return {"status": "refused", "reason": "invalid_request"}
        if self.stalls.stalled:
            return {"status": "stalled"}
        before = self.snapshot()
        result = run_script(
            self.host,
            arguments["script"],
            self.broker,
            timeout=min(30, self.deadline - time.monotonic()),
            cancelled=self.cancelled,
        )
        after = self.snapshot()
        if result["status"] == "executed":
            try:
                result["artifact"] = self.artifacts.put(result["output"])
            except Exception:
                result = {"status": "refused", "reason": "artifact_unavailable"}
        error = result.pop("error_fingerprint", None) or result.get("reason")
        state = self.stalls.observe(after, error, before != after)
        if state == "stalled":
            return {"status": "stalled"}
        if state == "intervene":
            return {
                "status": "intervention",
                "message": "Repeated failure or mutation oscillation. Use one alternative bounded diagnostic strategy; do not repeat the failed action.",
            }
        return result

    def page(self, attempt, ref, offset=0, size=MAX_OUTPUT):
        if self.cancelled.is_set() or time.monotonic() >= self.deadline:
            raise Denied("attempt_closed")
        result = self.artifacts.page(attempt, ref, offset, size)
        if self.cancelled.is_set() or time.monotonic() >= self.deadline:
            raise Denied("attempt_closed")
        return result

    def observe_exchange(self, body, reported_usage=None, **trusted_metrics):
        receipt = observation(
            body,
            reported_usage,
            goose_build=self.profile.goose_build,
            profile=self.profile.version,
            model=self.profile.model,
            route=self.profile.route,
            **trusted_metrics,
        )
        self.receipts.append(receipt)
        return receipt
