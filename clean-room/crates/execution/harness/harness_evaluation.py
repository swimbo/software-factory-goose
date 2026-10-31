#!/usr/bin/env python3
"""Offline Phase 11A receipts, frozen suites and paired gate. Never invokes a model."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import statistics
import subprocess
from factory_harness import Denied, canonical


def freeze_suite(tasks):
    if (
        not isinstance(tasks, list)
        or len(tasks) < 20
        or any(
            not isinstance(t, dict)
            or set(t) != {"id", "spec"}
            or not isinstance(t["id"], str)
            or not t["id"]
            or not isinstance(t["spec"], str)
            or not t["spec"]
            for t in tasks
        )
        or len({t["id"] for t in tasks}) != len(tasks)
    ):
        raise Denied("invalid_suite")
    tasks = sorted(tasks, key=lambda t: t["id"])
    return {
        "version": 1,
        "tasks": tasks,
        "sha256": hashlib.sha256(canonical(tasks).encode()).hexdigest(),
    }


def workspace_hash(root):
    """Hash actual tracked/untracked worktree content, not just git diff HEAD.

    Caller pauses mutations while collecting the snapshot. Symlinks are hashed as
    links, never followed into evaluator/host paths. Ignored private runtime is excluded.
    """
    root = Path(root)
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        capture_output=True,
    )
    digest = hashlib.sha256()
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in sorted(set(result.stdout.split(b"\0")) - {b""}):
            parts = name.decode("utf-8", "strict").split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise Denied("snapshot_unavailable")
            digest.update(len(name).to_bytes(8, "big"))
            digest.update(name)
            parent = os.dup(rootfd)
            try:
                for part in parts[:-1]:
                    nextfd = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent,
                    )
                    os.close(parent)
                    parent = nextfd
                try:
                    st = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    digest.update(b"deleted")
                    continue
                digest.update(stat.S_IFMT(st.st_mode).to_bytes(4, "big"))
                digest.update((st.st_mode & 0o111).to_bytes(4, "big"))
                if stat.S_ISLNK(st.st_mode):
                    data = os.readlink(parts[-1], dir_fd=parent).encode()
                elif stat.S_ISREG(st.st_mode):
                    fd = os.open(
                        parts[-1],
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=parent,
                    )
                    with os.fdopen(fd, "rb") as f:
                        current = os.fstat(f.fileno())
                        if (
                            not stat.S_ISREG(current.st_mode)
                            or current.st_size > 16 * 1024 * 1024
                        ):
                            raise Denied("snapshot_unavailable")
                        data = f.read(16 * 1024 * 1024 + 1)
                        if len(data) != current.st_size:
                            raise Denied("snapshot_unavailable")
                else:
                    raise Denied("snapshot_unavailable")
                digest.update(len(data).to_bytes(8, "big"))
                digest.update(data)
            except FileNotFoundError:
                digest.update(b"deleted")
            finally:
                os.close(parent)
    finally:
        os.close(rootfd)
    return digest.hexdigest()


def observation(
    body,
    usage,
    *,
    goose_build,
    profile,
    model,
    route,
    tool_result_bytes=None,
    billed_microusd=None,
    usage_rated_microusd=None,
    cost_basis=None,
    tariff_sha256=None,
    elapsed_ms=None,
    accepted=None,
):
    """Metadata-only record; original provider payload is never modified or retained.

    Token/cache numbers are provider-reported; bytes are not token estimates.
    Billed cost must come from the trusted accounting receipt, never inferred usage.
    """
    usage = usage if isinstance(usage, dict) else {}

    def count(v):
        return v if type(v) is int and v >= 0 else None

    details = usage.get("prompt_tokens_details")
    cache = details.get("cached_tokens") if isinstance(details, dict) else None
    cached = count(cache)
    prompt = count(usage.get("prompt_tokens"))
    if cached is not None and (prompt is None or cached > prompt):
        cached = None
    return {
        "version": 1,
        "goose_build": goose_build,
        "profile": profile,
        "model": model,
        "route": route,
        "request_sha256": hashlib.sha256(canonical(body).encode()).hexdigest(),
        "prompt_bytes": len(canonical(body.get("messages", [])).encode()),
        "prompt_tokens": prompt,
        "completion_tokens": count(usage.get("completion_tokens")),
        "cached_tokens": cached,
        "tool_result_bytes": count(tool_result_bytes),
        "model_round_trips": 1,
        "billed_microusd": count(billed_microusd),
        "usage_rated_microusd": count(usage_rated_microusd),
        "cost_basis": cost_basis
        if cost_basis in ("audited_usage_rated", "provider_billed")
        else None,
        "tariff_sha256": tariff_sha256
        if isinstance(tariff_sha256, str)
        and len(tariff_sha256) == 64
        and all(c in "0123456789abcdef" for c in tariff_sha256)
        else None,
        "elapsed_ms": count(elapsed_ms),
        "accepted": accepted if type(accepted) is bool else None,
    }


def evaluate(suite, rows):
    """Fail closed on incomplete pairs, provenance mismatch, safety or performance loss."""

    def failed(reason):
        return {
            "version": 1,
            "passed": False,
            "reason": reason,
            "candidate_enabled": False,
        }

    try:
        frozen = freeze_suite(suite["tasks"])
        if suite != frozen:
            return failed("invalid_suite")
        if not isinstance(rows, list) or len(rows) != len(suite["tasks"]) * 6:
            return failed("incomplete_pairs")
        basis = (
            rows[0].get("cost_basis", "provider_billed")
            if isinstance(rows[0], dict)
            else None
        )
        if basis not in ("provider_billed", "audited_usage_rated"):
            return failed("invalid_cost_basis")
        rated = basis == "audited_usage_rated"
        cost_key = "usage_rated_microusd" if rated else "billed_microusd"
        tariff = rows[0].get("tariff_sha256") if rated else None

        def digest(value):
            return (
                isinstance(value, str)
                and len(value) == 64
                and all(c in "0123456789abcdef" for c in value)
            )

        if rated and not digest(tariff):
            return failed("unknown_tariff")
        by_key = {}
        task_ids = {t["id"] for t in suite["tasks"]}
        identities = {"baseline": set(), "candidate": set()}
        for row in rows:
            if (
                not isinstance(row, dict)
                or row.get("task_id") not in task_ids
                or row.get("variant") not in identities
                or type(row.get("repeat")) is not int
                or row["repeat"] not in range(3)
                or row.get("suite_sha256") != suite["sha256"]
            ):
                return failed("invalid_receipt")
            key = row["task_id"], row["repeat"], row["variant"]
            if key in by_key:
                return failed("duplicate_receipt")
            if row.get("cost_basis", "provider_billed") != basis:
                return failed("unpaired_cost_basis")
            if rated and (
                row.get("tariff_sha256") != tariff
                or not digest(row.get("audit_sha256"))
                or "billed_microusd" in row
            ):
                return failed("invalid_cost_evidence")
            if not rated and "usage_rated_microusd" in row:
                return failed("invalid_cost_evidence")
            for field in (cost_key, "elapsed_ms", "budget"):
                if type(row.get(field)) is not int or row[field] < 0:
                    return failed("unknown_measurement")
            if (
                row["elapsed_ms"] == 0
                or row["budget"] == 0
                or row[cost_key] > row["budget"]
            ):
                return failed("invalid_measurement")
            if (
                type(row.get("accepted")) is not bool
                or row.get("independent") is not True
                or row.get("safety_passed") is not True
            ):
                return failed("unverified_outcome")
            if any(
                not isinstance(row.get(f), str) or not row[f]
                for f in ("model", "route", "goose_build", "profile")
            ):
                return failed("missing_provenance")
            identities[row["variant"]].add((row["goose_build"], row["profile"]))
            by_key[key] = row
        if any(len(x) != 1 for x in identities.values()):
            return failed("changed_harness")
        for task in task_ids:
            for repeat in range(3):
                a = by_key[task, repeat, "baseline"]
                b = by_key[task, repeat, "candidate"]
                if any(a[f] != b[f] for f in ("model", "route", "budget")):
                    return failed("unpaired_configuration")
        groups = {v: [r for r in rows if r["variant"] == v] for v in identities}
        counts = {v: sum(r["accepted"] for r in rs) for v, rs in groups.items()}
        if not counts["baseline"] or counts["candidate"] < counts["baseline"]:
            return failed("acceptance_regression")
        # Per-task cost includes failed repetitions, preventing cheap-success selection
        # from hiding expensive failed attempts. A zero-success task cannot be scored.
        costs = {}
        times = {}
        for variant, records in groups.items():
            task_costs = []
            task_times = []
            for task in task_ids:
                rs = [r for r in records if r["task_id"] == task]
                accepted = sum(r["accepted"] for r in rs)
                if not accepted:
                    return failed("unaccepted_task")
                task_costs.append(sum(r[cost_key] for r in rs) / accepted)
                task_times.append(sum(r["elapsed_ms"] for r in rs) / accepted)
            costs[variant] = statistics.median(task_costs)
            times[variant] = statistics.median(task_times)
        passed = (
            costs["baseline"] > 0
            and costs["candidate"] <= costs["baseline"] * 0.90
            and times["candidate"] <= times["baseline"] * 1.10
        )
        return {
            "version": 2 if rated else 1,
            "passed": passed,
            "reason": "passed" if passed else "performance_gate",
            "suite_sha256": suite["sha256"],
            "cost_basis": basis,
            "tariff_sha256": tariff,
            "accepted": counts,
            "median_cost_per_accepted_task_microusd": costs,
            "median_time_per_accepted_task_ms": times,
            "candidate_enabled": False,
        }
    except (KeyError, TypeError, ValueError, OverflowError):
        return failed("invalid_receipt")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("tasks", type=Path)
    gate = sub.add_parser("gate")
    gate.add_argument("suite", type=Path)
    gate.add_argument("receipts", type=Path)
    args = p.parse_args()
    if args.command == "freeze":
        print(canonical(freeze_suite(json.loads(args.tasks.read_text()))))
    else:
        result = evaluate(
            json.loads(args.suite.read_text()), json.loads(args.receipts.read_text())
        )
        print(canonical(result))
        raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
