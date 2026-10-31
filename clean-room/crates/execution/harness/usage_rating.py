"""Offline constant-tariff usage metric, never a billed debit or budget authority.

The supervisor owns manifest completeness. authenticate_usage must return evidence
from its protected authenticated collector, never worker/model claims. Its status
must be complete even for unsuccessful physical calls; unknown/error/partial usage
blocks totals. Input includes read/write cache; complete output totals include reasoning.
An unavailable reasoning detail stays None and is never added to output again. These
exclusive ownership conventions follow AI SDK total/inputTokenDetails semantics:
https://github.com/vercel/ai/blob/main/content/docs/07-reference/01-ai-sdk-core/01-generate-text.mdx
All integer timestamps are UTC epoch milliseconds.
No prices or provider usage normalization are inferred here.
"""

from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, localcontext, ROUND_CEILING
import hashlib
import json
import re
from typing import Optional


class UsageRatingRefused(Exception):
    """Fixed refusal codes only."""


def _require(condition, reason):
    if not condition:
        raise UsageRatingRefused(reason)


def _digest(s):
    return isinstance(s, str) and re.fullmatch("[0-9a-f]{64}", s) is not None


def _text(s):
    return (
        isinstance(s, str) and 0 < len(s) <= 256 and all(33 <= ord(c) <= 126 for c in s)
    )


def _hash(value):
    return hashlib.sha256(
        json.dumps(asdict(value), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _rate(s):
    _require(isinstance(s, str) and len(s) <= 64, "invalid_rate")
    try:
        d = Decimal(s)
    except InvalidOperation:
        raise UsageRatingRefused("invalid_rate") from None
    _require(
        d.is_finite()
        and 0 <= d <= 1000000
        and d.as_tuple().exponent >= -18
        and len(d.as_tuple().digits) <= 24,
        "invalid_rate",
    )
    _require(s == format(d, "f"), "noncanonical_rate")
    return d


@dataclass(frozen=True)
class TariffRate:
    provider: str
    model: str
    input_usd_per_token: str
    cache_read_usd_per_token: str
    cache_write_usd_per_token: str
    output_usd_per_token: str
    fixed_usd_per_call: str


@dataclass(frozen=True)
class TariffCard:
    version: str
    profile: str
    source_url: str
    source_sha256: str
    published_at: int
    valid_from: int
    valid_until: int
    rates: tuple[TariffRate, ...]

    def sha256(self):
        return _hash(self)


@dataclass(frozen=True)
class PhysicalCall:
    call_id: str
    sequence: int
    role: str
    provider: str
    model: str
    request_sha256: str
    dispatched_at: int


@dataclass(frozen=True)
class Manifest:
    attempt_id: str
    parent_request_id: str
    route_sha256: str
    request_sha256: str
    expected_call_ids: tuple[str, ...]
    calls: tuple[PhysicalCall, ...]

    def sha256(self):
        return _hash(self)


@dataclass(frozen=True)
class UsageEvidence:
    call_id: str
    provider: str
    model: str
    request_sha256: str
    input_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    output_tokens: int
    reasoning_tokens: Optional[int]
    trace_sha256: str
    status: str


class UsageRatedCollector:
    def __init__(self, tariff, expected_tariff_sha256, authenticate_usage):
        _require(
            type(tariff) is TariffCard and _digest(expected_tariff_sha256),
            "invalid_tariff",
        )
        _require(
            tariff.profile == "constant_peak"
            and _text(tariff.version)
            and _digest(tariff.source_sha256)
            and _text(tariff.source_url)
            and tariff.source_url.startswith("https://"),
            "invalid_tariff",
        )
        _require(
            all(
                type(t) is int and 0 <= t <= 2**63 - 1
                for t in (tariff.published_at, tariff.valid_from, tariff.valid_until)
            )
            and tariff.published_at <= tariff.valid_from < tariff.valid_until,
            "invalid_tariff_interval",
        )
        _require(
            type(tariff.rates) is tuple and 1 <= len(tariff.rates) <= 256,
            "invalid_tariff",
        )
        rates = {}
        for r in tariff.rates:
            _require(
                type(r) is TariffRate and _text(r.provider) and _text(r.model),
                "invalid_tariff_rate",
            )
            key = (r.provider, r.model)
            _require(key not in rates, "duplicate_tariff_rate")
            rates[key] = tuple(
                _rate(getattr(r, k))
                for k in (
                    "input_usd_per_token",
                    "cache_read_usd_per_token",
                    "cache_write_usd_per_token",
                    "output_usd_per_token",
                    "fixed_usd_per_call",
                )
            )
        _require(tariff.sha256() == expected_tariff_sha256, "tariff_binding_mismatch")
        _require(callable(authenticate_usage), "invalid_usage_collector")
        self.tariff, self.rates, self.authenticate_usage = (
            tariff,
            rates,
            authenticate_usage,
        )

    def validate_manifest(self, manifest):
        _require(
            type(manifest) is Manifest
            and _text(manifest.attempt_id)
            and _text(manifest.parent_request_id)
            and _digest(manifest.route_sha256)
            and _digest(manifest.request_sha256)
            and type(manifest.calls) is tuple
            and 1 <= len(manifest.calls) <= 256
            and type(manifest.expected_call_ids) is tuple,
            "invalid_manifest",
        )
        ids = []
        for i, c in enumerate(manifest.calls):
            _require(
                type(c) is PhysicalCall
                and _text(c.call_id)
                and type(c.sequence) is int
                and c.sequence == i
                and c.role in ("embedding", "classifier", "fallback", "answer")
                and _text(c.provider)
                and _text(c.model)
                and _digest(c.request_sha256)
                and type(c.dispatched_at) is int,
                "invalid_physical_call",
            )
            _require(c.call_id not in ids, "duplicate_physical_call")
            ids.append(c.call_id)
            _require(
                self.tariff.valid_from <= c.dispatched_at < self.tariff.valid_until,
                "tariff_interval_mismatch",
            )
            _require((c.provider, c.model) in self.rates, "tariff_model_mismatch")
        _require(
            tuple(ids) == manifest.expected_call_ids
            and any(c.role == "answer" for c in manifest.calls),
            "incomplete_manifest",
        )
        return manifest

    def collect(self, manifest):
        manifest = self.validate_manifest(manifest)
        receipts = []
        with localcontext() as ctx:
            ctx.prec = 80
            total = Decimal(0)
            for c in manifest.calls:
                u = self.authenticate_usage(c)
                _require(
                    type(u) is UsageEvidence and u.status == "complete",
                    "incomplete_usage",
                )
                _require(
                    (u.call_id, u.provider, u.model, u.request_sha256)
                    == (c.call_id, c.provider, c.model, c.request_sha256)
                    and _digest(u.trace_sha256),
                    "usage_binding_mismatch",
                )
                counts = (
                    u.input_tokens,
                    u.cache_read_tokens,
                    u.cache_write_tokens,
                    u.output_tokens,
                )
                _require(
                    all(type(n) is int and 0 <= n <= 2**63 - 1 for n in counts),
                    "invalid_usage_tokens",
                )
                _require(
                    u.cache_read_tokens + u.cache_write_tokens <= u.input_tokens
                    and (
                        u.reasoning_tokens is None
                        or (
                            type(u.reasoning_tokens) is int
                            and 0 <= u.reasoning_tokens <= u.output_tokens
                        )
                    ),
                    "unknown_usage_composition",
                )
                a, b, d, e, f = self.rates[(c.provider, c.model)]
                amount = (
                    (u.input_tokens - u.cache_read_tokens - u.cache_write_tokens) * a
                    + u.cache_read_tokens * b
                    + u.cache_write_tokens * d
                    + u.output_tokens * e
                    + f
                )
                total += amount
                receipts.append(
                    {
                        "call": asdict(c),
                        "usage": asdict(u),
                        "usage_rated_usd": format(amount, "f"),
                    }
                )
            micros = int((total * 1000000).to_integral_value(rounding=ROUND_CEILING))
        report = {
            "tariff": asdict(self.tariff),
            "manifest": asdict(manifest),
            "schema": 1,
            "source": "audited_usage_rated",
            "tariff_profile": self.tariff.profile,
            "tariff_sha256": self.tariff.sha256(),
            "manifest_sha256": manifest.sha256(),
            "attempt_id": manifest.attempt_id,
            "parent_request_id": manifest.parent_request_id,
            "route_sha256": manifest.route_sha256,
            "request_sha256": manifest.request_sha256,
            "usage_rated_usd": format(total, "f"),
            "usage_rated_microusd": micros,
            "rounding": "aggregate_ceiling_to_microusd",
            "receipts": receipts,
        }
        report["audit_sha256"] = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return report
