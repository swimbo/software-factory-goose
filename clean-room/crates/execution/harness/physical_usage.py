"""Protected physical capture → exact usage rating → the same spending owner.

No network inference, allowance, provider fact or launch authority is created here.
Only fixed Unix clients authenticate source/owner peers. Pure normalization does
not authenticate dictionaries; production must install the capture endpoint and
its complete durable permit/closure chain before using this collector.
"""

import copy
from dataclasses import asdict, dataclass
import hashlib
import os
import re

from factory_harness import canonical
from protected_spending_control import (
    ControlRefused,
    PrivateSpendingClient,
    _digest,
    _integer,
    _keys,
    NAME,
)
from usage_rating import (
    Manifest,
    PhysicalCall,
    UsageEvidence,
    UsageRatedCollector,
    UsageRatingRefused,
    _text,
)
from usage_spending import collect_usage_for_spending

MAX_CALLS = 32
USAGE_PATHS = frozenset(
    (
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "eval_count",
        "usage.prompt_tokens",
        "usage.completion_tokens",
        "usage.total_tokens",
        "usage.input_tokens",
        "usage.output_tokens",
        "usage.prompt_tokens_details.cached_tokens",
        "usage.prompt_tokens_details.cache_write_tokens",
        "usage.completion_tokens_details.reasoning_tokens",
        "usage.input_tokens_details.cached_tokens",
        "usage.output_tokens_details.reasoning_tokens",
    )
)


def _require(condition, reason):
    if not condition:
        raise UsageRatingRefused(reason)


def _name(value):
    return isinstance(value, str) and NAME.fullmatch(value) is not None


def payload_sha256(payload):
    try:
        return hashlib.sha256(canonical(payload).encode()).hexdigest()
    except Exception:
        raise UsageRatingRefused("invalid_capture_payload") from None


@dataclass(frozen=True)
class CaptureBinding:
    schema: int
    owner: str
    attempt_id: str
    call_id: str
    scope_sha256: str
    route_sha256: str
    request_sha256: str
    tariff_sha256: str
    physical_manifest_sha256: str

    def as_dict(self):
        return asdict(self)

    def validate(self):
        _require(
            type(self.schema) is int
            and self.schema == 1
            and _name(self.owner)
            and _name(self.call_id)
            and isinstance(self.attempt_id, str)
            and re.fullmatch(r"run_[0-9a-f]{64}", self.attempt_id) is not None
            and all(
                _digest(getattr(self, name))
                for name in (
                    "scope_sha256",
                    "route_sha256",
                    "request_sha256",
                    "tariff_sha256",
                    "physical_manifest_sha256",
                )
            ),
            "invalid_capture_binding",
        )


@dataclass(frozen=True)
class UsageSchemaProfile:
    version: str
    provider: str
    model: str
    roles: tuple[str, ...]
    review_sha256: str
    input_path: str
    output_path: str | None
    output_semantics: str
    cache_read_path: str | None
    cache_write_path: str | None
    reasoning_path: str | None

    def as_dict(self):
        return asdict(self)

    def validate(self):
        _require(
            _name(self.version)
            and _text(self.provider)
            and _text(self.model)
            and _digest(self.review_sha256)
            and type(self.roles) is tuple
            and 1 <= len(self.roles) <= 4
            and all(type(role) is str for role in self.roles)
            and len(set(self.roles)) == len(self.roles)
            and set(self.roles) <= {"embedding", "classifier", "fallback", "answer"}
            and type(self.input_path) is str
            and self.input_path in USAGE_PATHS
            and all(
                path is None or type(path) is str and path in USAGE_PATHS
                for path in (
                    self.output_path,
                    self.cache_read_path,
                    self.cache_write_path,
                    self.reasoning_path,
                )
            ),
            "invalid_usage_profile",
        )
        _require(
            (
                self.output_semantics == "inclusive_output_total"
                and self.output_path is not None
            )
            or (
                self.output_semantics == "embedding_no_output"
                and self.output_path is None
                and self.roles == ("embedding",)
            ),
            "invalid_output_semantics",
        )
        paths = [
            p
            for p in (
                self.input_path,
                self.output_path,
                self.cache_read_path,
                self.cache_write_path,
                self.reasoning_path,
            )
            if p is not None
        ]
        _require(len(paths) == len(set(paths)), "invalid_usage_profile")


def normalize_capture(envelope, binding, profiles, expected_components):
    """Pure strict conversion. The caller must authenticate envelope separately."""
    _require(type(binding) is CaptureBinding, "invalid_capture_binding")
    binding.validate()
    _require(
        type(profiles) is tuple and 1 <= len(profiles) <= 32, "invalid_usage_profile"
    )
    indexed = {}
    for profile in profiles:
        _require(type(profile) is UsageSchemaProfile, "invalid_usage_profile")
        profile.validate()
        for role in profile.roles:
            key = (profile.provider, profile.model, role)
            _require(key not in indexed, "duplicate_usage_profile")
            indexed[key] = profile
    _require(
        _keys(envelope, ("binding", "snapshot", "component_calls", "absent_components"))
        and type(envelope["binding"]) is dict
        and payload_sha256(envelope["binding"]) == payload_sha256(binding.as_dict()),
        "capture_binding_mismatch",
    )
    payload = {
        k: envelope[k] for k in ("snapshot", "component_calls", "absent_components")
    }
    _require(
        payload_sha256(payload) == binding.physical_manifest_sha256,
        "capture_digest_mismatch",
    )
    snapshot = payload["snapshot"]
    _require(
        _keys(snapshot, ("root_id", "sealed", "complete", "calls"))
        and snapshot["root_id"] == binding.call_id
        and snapshot["sealed"] is True
        and snapshot["complete"] is True
        and type(snapshot["calls"]) is list
        and 1 <= len(snapshot["calls"]) <= MAX_CALLS,
        "incomplete_capture",
    )
    calls, usages = [], {}
    mandatory = {
        "sequence",
        "permit_id",
        "request_sha256",
        "role",
        "provider",
        "model",
        "started_at",
        "status_code",
        "state",
        "usage",
        "trace_sha256",
    }
    for sequence, record in enumerate(snapshot["calls"]):
        _require(
            type(record) is dict
            and mandatory <= set(record)
            and set(record) <= mandatory | {"generation_id_sha256"}
            and type(record["sequence"]) is int
            and record["sequence"] == sequence
            and _name(record["permit_id"])
            and record["permit_id"] not in usages
            and _digest(record["request_sha256"])
            and _digest(record["trace_sha256"])
            and _text(record["provider"])
            and _text(record["model"])
            and type(record["role"]) is str
            and record["role"] in ("embedding", "classifier", "fallback", "answer")
            and (
                "generation_id_sha256" not in record
                or _digest(record["generation_id_sha256"])
            )
            and record["state"] == "complete"
            and _integer(record["status_code"], 200, 299)
            and _integer(record["started_at"], 0, 2**63 - 1)
            and type(record["usage"]) is dict
            and set(record["usage"]) <= USAGE_PATHS
            and all(_integer(n, 0, 2**63 - 1) for n in record["usage"].values()),
            "invalid_physical_record",
        )
        profile = indexed.get((record["provider"], record["model"], record["role"]))
        _require(profile is not None, "unreviewed_usage_schema")
        values = record["usage"]
        _require(
            profile.input_path in values
            and (profile.output_path is None or profile.output_path in values),
            "incomplete_usage",
        )
        call = PhysicalCall(
            record["permit_id"],
            sequence,
            record["role"],
            record["provider"],
            record["model"],
            record["request_sha256"],
            record["started_at"],
        )
        usages[call.call_id] = UsageEvidence(
            call.call_id,
            call.provider,
            call.model,
            call.request_sha256,
            values[profile.input_path],
            values.get(profile.cache_read_path),
            values.get(profile.cache_write_path),
            0
            if profile.output_semantics == "embedding_no_output"
            else values[profile.output_path],
            values.get(profile.reasoning_path),
            record["trace_sha256"],
            "complete",
        )
        calls.append(call)
    _require(
        type(expected_components) is tuple
        and 1 <= len(expected_components) <= MAX_CALLS
        and all(_name(v) for v in expected_components)
        and len(set(expected_components)) == len(expected_components)
        and type(payload["component_calls"]) is dict
        and type(payload["absent_components"]) is dict,
        "invalid_component_dispositions",
    )
    components, absent = payload["component_calls"], payload["absent_components"]
    _require(
        not set(components) & set(absent)
        and set(components) | set(absent) == set(expected_components)
        and all(_digest(v) for v in absent.values()),
        "incomplete_component_dispositions",
    )
    ids = []
    for values in components.values():
        _require(
            type(values) is list and values and all(_name(v) for v in values),
            "invalid_component_dispositions",
        )
        ids.extend(values)
    _require(
        len(ids) == len(set(ids)) and set(ids) == set(usages),
        "incomplete_component_dispositions",
    )
    manifest = Manifest(
        binding.attempt_id,
        binding.call_id,
        binding.route_sha256,
        binding.request_sha256,
        tuple(c.call_id for c in calls),
        tuple(calls),
    )
    return (
        manifest,
        usages,
        {k: tuple(v) for k, v in components.items()},
        copy.deepcopy(absent),
    )


class PrivateCollectorClient(PrivateSpendingClient):
    """Collector UID only; cannot reserve, bootstrap, revoke or grant allowance."""

    def __init__(
        self, path, *, service_uid, collector_uid, broker_uid, worker_uid, owner
    ):
        if len({0, service_uid, collector_uid, broker_uid, worker_uid}) != 5 or not all(
            _integer(v, 1, 2**31 - 1)
            for v in (service_uid, collector_uid, broker_uid, worker_uid)
        ):
            raise ControlRefused("private_spending_identity_unavailable")
        self.collector_uid = collector_uid
        super().__init__(
            path, service_uid=service_uid, broker_uid=collector_uid, owner=owner
        )

    def __call__(self, method, body):
        if (
            method not in ("claim_receipts", "complete")
            or os.geteuid() != self.collector_uid
        ):
            raise ControlRefused("private_spending_role_denied")
        fields = {
            "call_id",
            "request_sha256",
            "scope_sha256",
            "manifest_sha256",
            "generation_ids",
        }
        if method == "complete":
            fields |= {"route_sha256", "components", "usage_rating"}
        if (
            not _keys(body, fields)
            or not _name(body["call_id"])
            or not all(
                _digest(body[k])
                for k in ("request_sha256", "scope_sha256", "manifest_sha256")
            )
        ):
            raise ControlRefused("invalid_spending_request")
        ids = body["generation_ids"]
        if (
            type(ids) is not list
            or not 1 <= len(ids) <= MAX_CALLS
            or any(
                not isinstance(v, str) or re.fullmatch(r"usage_[0-9a-f]{64}", v) is None
                for v in ids
            )
            or ids != sorted(set(ids))
        ):
            raise ControlRefused("invalid_spending_request")
        if method == "complete":
            rating = body["usage_rating"]
            if (
                not _digest(body["route_sha256"])
                or type(body["components"]) is not dict
                or not 1 <= len(body["components"]) <= MAX_CALLS
                or not all(
                    _name(k) and _digest(v) for k, v in body["components"].items()
                )
                or not _keys(
                    rating, ("tariff_sha256", "audit_sha256", "usage_rated_microusd")
                )
                or not all(
                    _digest(rating[k]) for k in ("tariff_sha256", "audit_sha256")
                )
                or not _integer(rating["usage_rated_microusd"], 0, 750000)
            ):
                raise ControlRefused("invalid_spending_request")
        return self._send(method, canonical(body).encode())


class PrivateCaptureClient(PrivateSpendingClient):
    """Collector reads one authenticated immutable closure; no inference endpoint."""

    def __init__(
        self, path, *, service_uid, collector_uid, broker_uid, worker_uid, owner
    ):
        if len({0, service_uid, collector_uid, broker_uid, worker_uid}) != 5 or not all(
            _integer(v, 1, 2**31 - 1)
            for v in (service_uid, collector_uid, broker_uid, worker_uid)
        ):
            raise ControlRefused("private_spending_identity_unavailable")
        self.collector_uid = collector_uid
        super().__init__(
            path, service_uid=service_uid, broker_uid=collector_uid, owner=owner
        )

    def __call__(self, method, body):
        raise ControlRefused("private_capture_role_denied")

    def closed(self, binding):
        if (
            os.geteuid() != self.collector_uid
            or type(binding) is not CaptureBinding
            or binding.owner != self.owner
        ):
            raise ControlRefused("private_capture_role_denied")
        binding.validate()
        return self._send(
            "closed", canonical(binding.as_dict()).encode(), prefix="/capture/"
        )

    def persist_audit(self, binding, report):
        if (
            os.geteuid() != self.collector_uid
            or type(binding) is not CaptureBinding
            or binding.owner != self.owner
        ):
            raise ControlRefused("private_capture_role_denied")
        binding.validate()
        if (
            type(report) is not dict
            or not _digest(report.get("audit_sha256"))
            or payload_sha256({k: v for k, v in report.items() if k != "audit_sha256"})
            != report["audit_sha256"]
        ):
            raise ControlRefused("invalid_usage_audit")
        result = self._send(
            "audit",
            canonical({"binding": binding.as_dict(), "audit": report}).encode(),
            prefix="/capture/",
        )
        if (
            not _keys(result, ("audit_sha256", "stored"))
            or result["audit_sha256"] != report["audit_sha256"]
            or result["stored"] is not True
        ):
            raise ControlRefused("capture_audit_outcome_unknown")


class _PhysicalRatedCollector(UsageRatedCollector):
    def __init__(self, tariff, tariff_sha256, usages, source, binding, profiles):
        super().__init__(tariff, tariff_sha256, lambda c: usages[c.call_id])
        self.source, self.binding, self.profiles = source, binding, profiles

    def collect(self, manifest):
        report = super().collect(manifest)
        report["capture_sha256"] = self.binding.physical_manifest_sha256
        report["usage_schema_profiles"] = [p.as_dict() for p in self.profiles]
        report.pop("audit_sha256")
        report["audit_sha256"] = payload_sha256(report)
        try:
            self.source.persist_audit(self.binding, report)
        except Exception:
            raise UsageRatingRefused("capture_audit_outcome_unknown") from None
        return report


class PhysicalUsageCollector:
    def __init__(
        self,
        source,
        authority,
        tariff,
        expected_tariff_sha256,
        profiles,
        expected_components,
        *,
        mode="live",
    ):
        _require(
            type(source) is PrivateCaptureClient
            and type(authority) is PrivateCollectorClient
            and source.owner == authority.owner
            and source.collector_uid == authority.collector_uid
            and mode in ("live", "rehearsal"),
            "invalid_private_usage_services",
        )
        self.source, self.authority, self.mode = source, authority, mode
        self.tariff, self.tariff_sha256 = tariff, expected_tariff_sha256
        self.profiles, self.components = profiles, expected_components
        UsageRatedCollector(tariff, expected_tariff_sha256, lambda _: None)

    def settle(self, attempt, call, response):
        _require(
            type(attempt) is dict
            and type(call) is dict
            and type(response) is dict
            and attempt.get("budget_owner") == self.source.owner
            and attempt.get("cost_basis") == "audited_usage_rated"
            and attempt.get("tariff_sha256") == self.tariff_sha256
            and attempt.get("mode") == self.mode
            and all(
                response.get(k) == call.get(k)
                for k in ("call_id", "scope_sha256", "request_sha256")
            ),
            "spending_binding_mismatch",
        )
        binding = CaptureBinding(
            1,
            self.source.owner,
            attempt.get("attempt_id"),
            call.get("call_id"),
            call.get("scope_sha256"),
            attempt.get("route"),
            call.get("request_sha256"),
            self.tariff_sha256,
            response.get("physical_manifest_sha256"),
        )
        binding.validate()
        try:
            envelope = copy.deepcopy(self.source.closed(binding))
        except Exception:
            raise UsageRatingRefused("capture_outcome_unknown") from None
        manifest, usages, components, absent = normalize_capture(
            envelope, binding, self.profiles, self.components
        )
        collector = _PhysicalRatedCollector(
            self.tariff, self.tariff_sha256, usages, self.source, binding, self.profiles
        )
        report = collect_usage_for_spending(
            manifest,
            collector=collector,
            authority=self.authority,
            call_id=binding.call_id,
            scope_sha256=binding.scope_sha256,
            route_sha256=binding.route_sha256,
            request_sha256=binding.request_sha256,
            expected_components=self.components,
            component_calls=components,
            absent_components=absent,
        )
        return {
            "call_id": binding.call_id,
            "scope_sha256": binding.scope_sha256,
            "request_sha256": binding.request_sha256,
            "route_sha256": binding.route_sha256,
            "physical_manifest_sha256": binding.physical_manifest_sha256,
            "billing_receipt_sha256": payload_sha256(report),
            "usage_rated_microusd": report["usage_rated_microusd"],
            "usage_rated_usd": report["usage_rated_usd"],
            "tariff_sha256": self.tariff_sha256,
            "audit_sha256": report["audit_sha256"],
            "source": "synthetic"
            if self.mode == "rehearsal"
            else "audited_usage_rated",
            "all_calls_complete": True,
        }
