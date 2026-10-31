#!/usr/bin/env python3
"""Resumable paired orchestration through a trusted protected runtime adapter.

This owns scheduling and sanitized receipts, never money or inference authority.
The protected supervisor supplies an authenticated adapter and prevents workers
from accessing this directory. An adapter's dictionaries are not self-authenticating
evidence. The CLI only inspects an existing ledger; it cannot select code to run.
"""

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from factory_harness import canonical
from harness_evaluation import evaluate, freeze_suite


MAX_LEDGER_BYTES = 2 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
STAGES = {
    "pending",
    "admitting",
    "day_cap",
    "denied",
    "generating",
    "generated",
    "evaluating",
    "evaluated",
    "collecting",
    "complete",
}
IN_FLIGHT = {"admitting", "generating", "evaluating", "collecting"}
RECORD_KEYS = {
    "stage",
    "admission",
    "generation",
    "evaluation",
    "billing",
    "reconciliation_receipt_sha256",
}


class RunnerRefused(Exception):
    """Fixed sanitized reason; no adapter exceptions or trace contents escape."""


def _digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _hash(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _integer(value, minimum=0, maximum=(1 << 63) - 1):
    return type(value) is int and minimum <= value <= maximum


def _keys(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RunnerRefused("invalid_ledger")
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                RunnerRefused("invalid_ledger")
            ),
        )
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise RunnerRefused("invalid_ledger") from None


def _configuration(suite, config):
    try:
        if suite != freeze_suite(suite["tasks"]) or len(suite["tasks"]) != 20:
            raise RunnerRefused("invalid_suite")
    except (KeyError, TypeError, ValueError):
        raise RunnerRefused("invalid_suite") from None
    if not _keys(
        config,
        {
            "benchmark_id",
            "mode",
            "model",
            "route",
            "goose_build",
            "profiles",
            "budget",
            "daily_cap",
            "budget_owner",
        },
    ):
        raise RunnerRefused("invalid_configuration")
    if not (
        _identifier(config["benchmark_id"])
        and _identifier(config["budget_owner"])
        and config["mode"] in ("live", "rehearsal")
        and isinstance(config["model"], str)
        and 0 < len(config["model"]) <= 256
        and all(33 <= ord(c) <= 126 for c in config["model"])
        and _digest(config["route"])
        and _digest(config["goose_build"])
        and _keys(config["profiles"], ("baseline", "candidate"))
        and all(_digest(v) for v in config["profiles"].values())
        and type(config["budget"]) is int
        and config["budget"] == 750000
        and type(config["daily_cap"]) is int
        and config["daily_cap"] == 5000000
        and all(_identifier(t["id"]) for t in suite["tasks"])
    ):
        raise RunnerRefused("invalid_configuration")


def schedule(suite, config):
    """Twenty tasks, three repeats, adjacent counterbalanced baseline/candidate pairs."""
    _configuration(suite, config)
    config_sha = _hash(config)
    result = []
    for repeat in range(3):
        for index, task in enumerate(suite["tasks"]):
            order = (
                ("baseline", "candidate")
                if (index + repeat) % 2 == 0
                else ("candidate", "baseline")
            )
            for variant in order:
                identity = {
                    "benchmark_id": config["benchmark_id"],
                    "budget_owner": config["budget_owner"],
                    "suite_sha256": suite["sha256"],
                    "task_id": task["id"],
                    "repeat": repeat,
                    "variant": variant,
                }
                result.append(
                    {
                        "attempt_id": "run_" + _hash(identity),
                        "task_id": task["id"],
                        "repeat": repeat,
                        "variant": variant,
                        "suite_sha256": suite["sha256"],
                        "config_sha256": config_sha,
                        "model": config["model"],
                        "route": config["route"],
                        "goose_build": config["goose_build"],
                        "profile": config["profiles"][variant],
                        "budget": config["budget"],
                        "daily_cap": config["daily_cap"],
                        "budget_owner": config["budget_owner"],
                        "mode": config["mode"],
                    }
                )
    return result


def _admission(value, attempt):
    if not (
        _keys(value, ("attempt_id", "status", "authority_receipt_sha256"))
        and value["attempt_id"] == attempt["attempt_id"]
        and value["status"] in ("allowed", "day_cap", "denied")
        and _digest(value["authority_receipt_sha256"])
    ):
        raise RunnerRefused("invalid_admission_receipt")


def _generation(value, attempt):
    if not _keys(
        value,
        (
            "attempt_id",
            "artifact_sha256",
            "dispatch_manifest_sha256",
            "call_ids",
            "elapsed_ms",
            "generation_receipt_sha256",
            "model",
            "route",
            "goose_build",
            "profile",
            "outcome",
            "live",
        ),
    ):
        raise RunnerRefused("invalid_generation_receipt")
    if not (
        value["attempt_id"] == attempt["attempt_id"]
        and all(
            value[k] == attempt[k] for k in ("model", "route", "goose_build", "profile")
        )
        and all(
            _digest(value[k])
            for k in (
                "artifact_sha256",
                "dispatch_manifest_sha256",
                "generation_receipt_sha256",
            )
        )
        and type(value["call_ids"]) is list
        and 1 <= len(value["call_ids"]) <= 256
        and all(_identifier(v) for v in value["call_ids"])
        and len(set(value["call_ids"])) == len(value["call_ids"])
        and _integer(value["elapsed_ms"], 1)
        and value["outcome"] in ("completed", "failed", "stalled", "cancelled")
        and type(value["live"]) is bool
        and value["live"] == (attempt["mode"] == "live")
    ):
        raise RunnerRefused("invalid_generation_receipt")


def _evaluation(value, attempt, generation):
    if not (
        _keys(
            value,
            (
                "attempt_id",
                "artifact_sha256",
                "accepted",
                "independent",
                "safety_passed",
                "evaluation_receipt_sha256",
                "evaluator_build",
            ),
        )
        and value["attempt_id"] == attempt["attempt_id"]
        and value["artifact_sha256"] == generation["artifact_sha256"]
        and type(value["accepted"]) is bool
        and value["independent"] is True
        and type(value["safety_passed"]) is bool
        and _digest(value["evaluation_receipt_sha256"])
        and _digest(value["evaluator_build"])
        and (not value["accepted"] or generation["outcome"] == "completed")
    ):
        raise RunnerRefused("invalid_evaluation_receipt")


def _billing(value, attempt, generation):
    if not (
        _keys(
            value,
            (
                "attempt_id",
                "dispatch_manifest_sha256",
                "call_ids",
                "billed_microusd",
                "receipt_sha256",
                "source",
                "all_calls_complete",
            ),
        )
        and value["attempt_id"] == attempt["attempt_id"]
        and value["dispatch_manifest_sha256"] == generation["dispatch_manifest_sha256"]
        and value["call_ids"] == generation["call_ids"]
        and _integer(value["billed_microusd"], 0, attempt["budget"])
        and _digest(value["receipt_sha256"])
        and value["source"]
        == ("provider_billed" if attempt["mode"] == "live" else "synthetic")
        and value["all_calls_complete"] is True
    ):
        raise RunnerRefused("invalid_billing_receipt")


def _record():
    return dict(
        stage="pending",
        admission=None,
        generation=None,
        evaluation=None,
        billing=None,
        reconciliation_receipt_sha256=None,
    )


class Runner:
    def __init__(self, directory, suite, config, *, create=False):
        self.suite = copy.deepcopy(suite)
        self.config = copy.deepcopy(config)
        self.attempts = schedule(self.suite, self.config)
        self._by_id = {a["attempt_id"]: a for a in self.attempts}
        self._dirfd = self._lockfd = None
        self._broken = False
        try:
            directory = Path(directory)
            if create:
                directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            self._dirfd = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            self._private(os.fstat(self._dirfd), directory=True)
            self._lockfd = os.open(
                "runner.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self._dirfd,
            )
            self._private(os.fstat(self._lockfd))
            fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create:
                initial = {
                    "schema": 1,
                    "suite_sha256": suite["sha256"],
                    "config": self.config,
                    "config_sha256": _hash(self.config),
                    "records": {a["attempt_id"]: _record() for a in self.attempts},
                }
                self._validate(initial)
                self._persist(initial, initial=True)
            self.state = self._load()
            self._validate(self.state)
        except RunnerRefused:
            self.close()
            raise
        except (OSError, ValueError, TypeError, RecursionError):
            self.close()
            raise RunnerRefused("ledger_unavailable") from None

    @staticmethod
    def _private(st, *, directory=False):
        good_type = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
        if (
            not good_type
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600)
            or (not directory and st.st_nlink != 1)
        ):
            raise RunnerRefused("ledger_not_private")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        for name in ("_lockfd", "_dirfd"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def _load(self):
        fd = os.open(
            "ledger.json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._dirfd,
        )
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            self._private(st)
            if not 0 < st.st_size <= MAX_LEDGER_BYTES:
                raise RunnerRefused("invalid_ledger")
            data = stream.read(MAX_LEDGER_BYTES + 1)
            if len(data) != st.st_size:
                raise RunnerRefused("invalid_ledger")
        return _json(data)

    def _persist(self, state, *, initial=False):
        raw = canonical(state).encode()
        if len(raw) > MAX_LEDGER_BYTES:
            raise RunnerRefused("ledger_overflow")
        name = "ledger.json" if initial else ".ledger-" + secrets.token_hex(16)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._dirfd,
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if not initial:
                os.replace(
                    name, "ledger.json", src_dir_fd=self._dirfd, dst_dir_fd=self._dirfd
                )
            os.fsync(self._dirfd)
        finally:
            if not initial:
                try:
                    os.unlink(name, dir_fd=self._dirfd)
                except FileNotFoundError:
                    pass

    def _validate(self, state):
        if not (
            _keys(
                state, ("schema", "suite_sha256", "config", "config_sha256", "records")
            )
            and type(state["schema"]) is int
            and state["schema"] == 1
            and state["suite_sha256"] == self.suite["sha256"]
            and state["config"] == self.config
            and state["config_sha256"] == _hash(self.config)
            and type(state["records"]) is dict
            and set(state["records"]) == set(self._by_id)
        ):
            raise RunnerRefused("ledger_binding_mismatch")
        encountered_unfinished = False
        unsafe = False
        evaluator_build = None
        global_calls = set()
        for attempt in self.attempts:
            record = state["records"][attempt["attempt_id"]]
            if not _keys(record, RECORD_KEYS) or record["stage"] not in STAGES:
                raise RunnerRefused("invalid_ledger")
            stage = record["stage"]
            if (encountered_unfinished or unsafe) and stage != "pending":
                raise RunnerRefused("invalid_ledger_order")
            encountered_unfinished = encountered_unfinished or stage != "complete"
            if record["reconciliation_receipt_sha256"] is not None and not _digest(
                record["reconciliation_receipt_sha256"]
            ):
                raise RunnerRefused("invalid_ledger")
            admission, generation, evaluation, billing = (
                record[k] for k in ("admission", "generation", "evaluation", "billing")
            )
            if stage in ("pending", "admitting"):
                if any(
                    v is not None for v in (admission, generation, evaluation, billing)
                ):
                    raise RunnerRefused("invalid_ledger")
                continue
            _admission(admission, attempt)
            if stage in ("day_cap", "denied"):
                if admission["status"] != stage or any(
                    v is not None for v in (generation, evaluation, billing)
                ):
                    raise RunnerRefused("invalid_ledger")
                continue
            if admission["status"] != "allowed":
                raise RunnerRefused("invalid_ledger")
            if stage == "generating":
                if any(v is not None for v in (generation, evaluation, billing)):
                    raise RunnerRefused("invalid_ledger")
                continue
            _generation(generation, attempt)
            if global_calls.intersection(generation["call_ids"]):
                raise RunnerRefused("reused_dispatch_identity")
            global_calls.update(generation["call_ids"])
            if stage in ("generated", "evaluating"):
                if evaluation is not None or billing is not None:
                    raise RunnerRefused("invalid_ledger")
                continue
            _evaluation(evaluation, attempt, generation)
            if evaluator_build is None:
                evaluator_build = evaluation["evaluator_build"]
            elif evaluation["evaluator_build"] != evaluator_build:
                raise RunnerRefused("changed_independent_evaluator")
            if stage in ("evaluated", "collecting"):
                if billing is not None:
                    raise RunnerRefused("invalid_ledger")
                continue
            _billing(billing, attempt, generation)
            unsafe = not evaluation["safety_passed"]

    def _transition(self, attempt_id, **changes):
        if self._broken or self._dirfd is None:
            raise RunnerRefused("ledger_unavailable")
        candidate = copy.deepcopy(self.state)
        candidate["records"][attempt_id].update(changes)
        self._validate(candidate)
        try:
            self._persist(candidate)
        except Exception:
            self._broken = True
            raise RunnerRefused("ledger_unavailable") from None
        self.state = candidate

    def _row(self, attempt, record):
        return {
            k: attempt[k]
            for k in (
                "task_id",
                "repeat",
                "variant",
                "suite_sha256",
                "model",
                "route",
                "goose_build",
                "profile",
                "budget",
            )
        } | {
            "billed_microusd": record["billing"]["billed_microusd"],
            "elapsed_ms": record["generation"]["elapsed_ms"],
            "accepted": record["evaluation"]["accepted"],
            "independent": record["evaluation"]["independent"],
            "safety_passed": record["evaluation"]["safety_passed"],
            "billing_receipt_sha256": record["billing"]["receipt_sha256"],
            "evaluation_receipt_sha256": record["evaluation"][
                "evaluation_receipt_sha256"
            ],
        }

    def status(self):
        self._validate(self.state)
        completed = [
            self._row(a, self.state["records"][a["attempt_id"]])
            for a in self.attempts
            if self.state["records"][a["attempt_id"]]["stage"] == "complete"
        ]
        gate = evaluate(self.suite, completed)
        if self.config["mode"] == "rehearsal":
            gate = {
                "version": 1,
                "passed": False,
                "reason": "synthetic_evidence",
                "candidate_enabled": False,
            }
        return {
            "completed_runs": len(completed),
            "completed_live_runs": len(completed)
            if self.config["mode"] == "live"
            else 0,
            "required_runs": 120,
            "candidate_enabled": False,
            "performance_gate": gate,
        }

    def _report(self, status, attempt=None):
        return {"status": status, "candidate_enabled": False} | (
            {"attempt_id": attempt["attempt_id"]} if attempt else {}
        )

    def run_next(self, adapter):
        """Run at most one paid attempt; every admission/dispatch is adapter-owned.

        admit(attempt), generate(attempt,admission), evaluate(attempt,generation),
        collect(attempt,generation) must be bounded protected calls. The generator
        receives no evaluator details or collector credentials through this API.
        """
        if self._broken or self._dirfd is None:
            raise RunnerRefused("ledger_unavailable")
        self._validate(self.state)
        for attempt in self.attempts:
            record = self.state["records"][attempt["attempt_id"]]
            if record["stage"] == "complete":
                if not record["evaluation"]["safety_passed"]:
                    return self._report("safety_regression", attempt)
                continue
            break
        else:
            return self._report("finished")
        attempt = copy.deepcopy(attempt)
        attempt_id = attempt["attempt_id"]
        if record["stage"] in IN_FLIGHT:
            return self._report("reconciliation_required", attempt)
        if record["stage"] == "denied":
            return self._report("denied", attempt)
        try:
            if record["stage"] in ("pending", "day_cap"):
                self._transition(attempt_id, stage="admitting", admission=None)
                admission = adapter.admit(copy.deepcopy(attempt))
                _admission(admission, attempt)
                stage = (
                    "generating"
                    if admission["status"] == "allowed"
                    else admission["status"]
                )
                self._transition(
                    attempt_id, stage=stage, admission=copy.deepcopy(admission)
                )
                if stage != "generating":
                    return self._report(stage, attempt)
                generation = adapter.generate(
                    copy.deepcopy(attempt), copy.deepcopy(admission)
                )
                _generation(generation, attempt)
                self._transition(
                    attempt_id, stage="generated", generation=copy.deepcopy(generation)
                )
            record = self.state["records"][attempt_id]
            if record["stage"] == "generated":
                self._transition(attempt_id, stage="evaluating")
                evaluation = adapter.evaluate(
                    copy.deepcopy(attempt), copy.deepcopy(record["generation"])
                )
                _evaluation(evaluation, attempt, record["generation"])
                self._transition(
                    attempt_id, stage="evaluated", evaluation=copy.deepcopy(evaluation)
                )
            record = self.state["records"][attempt_id]
            if record["stage"] == "evaluated":
                self._transition(attempt_id, stage="collecting")
                billing = adapter.collect(
                    copy.deepcopy(attempt), copy.deepcopy(record["generation"])
                )
                _billing(billing, attempt, record["generation"])
                self._transition(
                    attempt_id, stage="complete", billing=copy.deepcopy(billing)
                )
        except RunnerRefused:
            if self._broken:
                raise
            return self._report("reconciliation_required", attempt)
        except Exception:
            return self._report("reconciliation_required", attempt)
        if not self.state["records"][attempt_id]["evaluation"]["safety_passed"]:
            return self._report("safety_regression", attempt)
        return self._report("completed", attempt)

    def run(self, adapter, *, max_attempts=120):
        if not _integer(max_attempts, 1, 120):
            raise RunnerRefused("invalid_attempt_limit")
        for _ in range(max_attempts):
            result = self.run_next(adapter)
            if result["status"] != "completed":
                return result
        return (
            self._report("finished")
            if self.status()["completed_runs"] == 120
            else self._report("bounded_stop")
        )

    def reconcile(self, adapter, attempt_id):
        """Explicit trusted reconciliation only; never invokes generation itself."""
        if self._broken or self._dirfd is None:
            raise RunnerRefused("ledger_unavailable")
        self._validate(self.state)
        if attempt_id not in self._by_id:
            raise RunnerRefused("unknown_attempt")
        attempt = copy.deepcopy(self._by_id[attempt_id])
        record = copy.deepcopy(self.state["records"][attempt_id])
        if record["stage"] not in IN_FLIGHT:
            raise RunnerRefused("reconciliation_not_required")
        try:
            value = adapter.reconcile(copy.deepcopy(attempt), copy.deepcopy(record))
            if (
                not _keys(
                    value,
                    (
                        "attempt_id",
                        "status",
                        "admission",
                        "generation",
                        "evaluation",
                        "billing",
                        "reconciliation_receipt_sha256",
                    ),
                )
                or value["attempt_id"] != attempt_id
                or not _digest(value["reconciliation_receipt_sha256"])
            ):
                raise RunnerRefused("invalid_reconciliation")
            status = value["status"]
            if status == "unknown":
                return self._report("reconciliation_required", attempt)
            if status == "not_dispatched":
                if record["generation"] is not None or any(
                    value[k] is not None
                    for k in ("admission", "generation", "evaluation", "billing")
                ):
                    raise RunnerRefused("invalid_reconciliation")
                self._transition(
                    attempt_id,
                    **(
                        _record()
                        | {
                            "reconciliation_receipt_sha256": value[
                                "reconciliation_receipt_sha256"
                            ]
                        }
                    ),
                )
                return self._report("pending", attempt)
            if status not in {"generated", "evaluated", "complete"}:
                raise RunnerRefused("invalid_reconciliation")
            for field in ("admission", "generation", "evaluation", "billing"):
                if record[field] is not None and record[field] != value[field]:
                    raise RunnerRefused("reconciliation_conflict")
            if (
                status == "generated"
                and any(value[k] is not None for k in ("evaluation", "billing"))
                or status == "evaluated"
                and value["billing"] is not None
            ):
                raise RunnerRefused("invalid_reconciliation")
            self._transition(
                attempt_id,
                stage=status,
                **{
                    k: copy.deepcopy(value[k])
                    for k in (
                        "admission",
                        "generation",
                        "evaluation",
                        "billing",
                        "reconciliation_receipt_sha256",
                    )
                },
            )
            if status == "complete" and not value["evaluation"]["safety_passed"]:
                return self._report("safety_regression", attempt)
            return self._report(
                "completed" if status == "complete" else status, attempt
            )
        except Exception:
            if self._broken:
                raise RunnerRefused("ledger_unavailable") from None
            return self._report("reconciliation_required", attempt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "gate"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        with Runner(
            args.directory,
            _json(args.suite.read_bytes()),
            _json(args.config.read_bytes()),
        ) as runner:
            status = runner.status()
            print(canonical(status))
            if args.command == "gate" and not status["performance_gate"]["passed"]:
                return 1
            return 0
    except (RunnerRefused, OSError):
        print(canonical({"status": "refused", "candidate_enabled": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
