"""Trusted, unregistered physical-call billing collector; never a worker tool.

The supervisor must supply a complete immutable dispatch manifest and an atomic,
durable generation-claim callback shared across attempts. Neither a worker's JSON
nor Bifrost's incomplete log tree can establish this completeness. No inference is
sent here. Ollama account aggregates and catalog estimates are not receipts.

Vercel fields: https://vercel.com/docs/ai-gateway/sdks-and-apis/rest-api
Non-BYOK total_cost is the recorded balance debit including surcharges; BYOK
upstream_inference_cost is only a market estimate and is deliberately refused.
"""

from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys


MAX_BYTES = 32768
TIMEOUT = 5
GENERATION = re.compile(r"gen_[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ROLES = frozenset(("embedding", "classifier", "fallback", "answer"))


class BillingRefused(Exception):
    """Only fixed reason codes may cross the collector boundary."""


def _generation(value):
    if not isinstance(value, str) or GENERATION.fullmatch(value) is None:
        raise BillingRefused("invalid_generation")


def _digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _name(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


@dataclass(frozen=True)
class PhysicalCall:
    call_id: str
    sequence: int
    role: str
    provider: str
    model: str
    generation_id: str
    receipt_source: str


@dataclass(frozen=True)
class Manifest:
    attempt_id: str
    parent_request_id: str
    route_sha256: str
    request_sha256: str
    expected_call_ids: tuple[str, ...]
    calls: tuple[PhysicalCall, ...]

    def sha256(self):
        return hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def freeze_manifest(
    *,
    attempt_id,
    parent_request_id,
    route_sha256,
    request_sha256,
    expected_call_ids,
    calls,
):
    """Trusted supervisor seam, not an attestation of caller-supplied claims.

    expected_call_ids comes from the sole durable dispatch journal, including
    unsuccessful/ambiguous attempts and every retry, not from collected receipts.
    An unresolved generation or unsupported backend blocks the entire aggregate.
    """
    if not (
        _name(attempt_id)
        and _name(parent_request_id)
        and _digest(route_sha256)
        and _digest(request_sha256)
        and type(calls) is tuple
        and type(expected_call_ids) is tuple
        and 1 <= len(calls) <= 256
    ):
        raise BillingRefused("invalid_manifest")
    ids, generations = [], set()
    for sequence, call in enumerate(calls):
        if not isinstance(call, PhysicalCall) or not (
            _name(call.call_id)
            and type(call.sequence) is int
            and call.sequence == sequence
            and isinstance(call.role, str)
            and call.role in ROLES
            and call.receipt_source == "vercel_generation"
            and all(
                isinstance(s, str)
                and 0 < len(s) <= 256
                and all(33 <= ord(c) <= 126 for c in s)
                for s in (call.provider, call.model)
            )
        ):
            raise BillingRefused("invalid_physical_call")
        _generation(call.generation_id)
        if call.generation_id in generations or call.call_id in ids:
            raise BillingRefused("duplicate_physical_call")
        generations.add(call.generation_id)
        ids.append(call.call_id)
    if tuple(ids) != expected_call_ids or not any(c.role == "answer" for c in calls):
        raise BillingRefused("incomplete_manifest")
    return Manifest(
        attempt_id,
        parent_request_id,
        route_sha256,
        request_sha256,
        expected_call_ids,
        calls,
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BillingRefused("invalid_receipt")
        result[key] = value
    return result


def _money(value):
    if type(value) not in (int, Decimal, str):
        raise BillingRefused("unknown_billed_amount")
    if isinstance(value, str) and len(value) > 64:
        raise BillingRefused("invalid_billed_amount")
    try:
        amount = Decimal(value)
    except (InvalidOperation, ValueError):
        raise BillingRefused("invalid_billed_amount") from None
    if not amount.is_finite() or not 0 <= amount <= Decimal("1000000"):
        raise BillingRefused("invalid_billed_amount")
    if amount.as_tuple().exponent < -18 or len(amount.as_tuple().digits) > 24:
        raise BillingRefused("invalid_billed_amount")
    return amount


@dataclass(frozen=True)
class BilledReceipt:
    generation_id: str
    provider: str
    model: str
    billed_usd: Decimal
    source: str
    response_sha256: str


def parse_generation(raw, call):
    """Only call this on bytes from the authenticated lookup, never model output."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise BillingRefused("invalid_receipt")
    if not isinstance(call, PhysicalCall) or call.receipt_source != "vercel_generation":
        raise BillingRefused("unsupported_billing_source")
    try:
        root = json.loads(
            raw,
            parse_float=Decimal,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                BillingRefused("invalid_receipt")
            ),
        )
        data = root["data"]
        if not isinstance(data, dict) or (
            data["id"] != call.generation_id
            or data["provider_name"] != call.provider
            or data["model"] != call.model
            or data["is_byok"] is not False
            or data.get("estimated", False) is not False
        ):
            raise BillingRefused("receipt_binding_mismatch")
        amount = _money(data["total_cost"])
        if _money(data["gateway_cost"]) != amount or _money(data["usage"]) != amount:
            raise BillingRefused("receipt_cost_mismatch")
        return BilledReceipt(
            call.generation_id,
            call.provider,
            call.model,
            amount,
            "vercel_generation",
            hashlib.sha256(raw).hexdigest(),
        )
    except (KeyError, TypeError, ValueError, RecursionError, UnicodeError):
        raise BillingRefused("invalid_receipt") from None


class ReceiptCollector:
    def __init__(self, client, claim_generations):
        """claim_generations(ids,binding) must atomically persist all claims.

        Exact binding replay is allowed for receipt lookup; a different manifest
        must refuse any previously claimed generation, including after restart.
        The caller supplies this authority; this collector creates no new ledger.
        """
        self.client = client
        self.claim_generations = claim_generations

    def collect(self, manifest):
        if not isinstance(manifest, Manifest):
            raise BillingRefused("invalid_manifest")
        frozen = freeze_manifest(**asdict_manifest(manifest))
        binding = frozen.sha256()
        self.claim_generations(tuple(c.generation_id for c in frozen.calls), binding)
        receipts = [
            parse_generation(self.client.lookup(c.generation_id), c)
            for c in frozen.calls
        ]
        with localcontext() as context:
            context.prec = 48
            total = sum((r.billed_usd for r in receipts), Decimal(0))
            micros = int((total * 1000000).to_integral_value(rounding=ROUND_CEILING))
        return {
            "schema": 1,
            "manifest_sha256": binding,
            "attempt_id": frozen.attempt_id,
            "parent_request_id": frozen.parent_request_id,
            "route_sha256": frozen.route_sha256,
            "request_sha256": frozen.request_sha256,
            "billed_usd": format(total, "f"),
            "billed_microusd": micros,
            "rounding": "aggregate_ceiling_to_microusd",
            "receipts": [
                dict(asdict(r), billed_usd=format(r.billed_usd, "f")) for r in receipts
            ],
        }


def asdict_manifest(manifest):
    # dataclasses.asdict recursively changes PhysicalCall to dict; preserve types.
    return {name: getattr(manifest, name) for name in Manifest.__dataclass_fields__}


def _lookup_https(credential, generation_id):
    """One fixed HTTPS GET, no redirect/proxy machinery or inference dispatch."""
    connection = http.client.HTTPSConnection(
        "ai-gateway.vercel.sh", timeout=TIMEOUT, context=ssl.create_default_context()
    )
    try:
        connection.request(
            "GET",
            "/v1/generation?id=" + generation_id,
            headers={
                "Authorization": "Bearer " + credential,
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status == 404:
            raise BillingRefused("receipt_pending")
        if response.status != 200:
            raise BillingRefused("receipt_lookup_failed")
        if response.getheader("Content-Type", "").split(";", 1)[
            0
        ].strip().lower() != "application/json" or response.getheader(
            "Content-Encoding"
        ) not in (None, "identity"):
            raise BillingRefused("invalid_receipt_http")
        length = response.getheader("Content-Length")
        if length is not None and (
            len(length) > 10
            or not length.isascii()
            or not length.isdecimal()
            or not 0 < int(length) <= MAX_BYTES
        ):
            raise BillingRefused("receipt_overflow")
        raw = response.read(MAX_BYTES + 1)
        if not 0 < len(raw) <= MAX_BYTES or (
            length is not None and len(raw) != int(length)
        ):
            raise BillingRefused("invalid_receipt_http")
        return raw
    finally:
        connection.close()


class VercelGenerationClient:
    def __init__(self, credential):
        if (
            not isinstance(credential, str)
            or not 1 <= len(credential) <= 4096
            or not all(33 <= ord(c) <= 126 for c in credential)
        ):
            raise BillingRefused("credential_unavailable")
        self._credential = credential

    def lookup(self, generation_id):
        _generation(generation_id)
        try:
            # A disposable child bounds DNS, TLS, header parsing and slow-drip
            # response time together. Secrets travel on stdin, never argv/env.
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--lookup"],
                input=json.dumps([self._credential, generation_id]).encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=TIMEOUT,
                env={},
                cwd="/",
                check=False,
            )
            if completed.returncode != 0:
                if completed.returncode == 4:
                    raise BillingRefused("receipt_pending")
                raise BillingRefused("receipt_lookup_failed")
            if not completed.stdout.startswith(b"200\n"):
                raise BillingRefused("invalid_receipt_http")
            raw = completed.stdout[4:]
            if not 0 < len(raw) <= MAX_BYTES:
                raise BillingRefused("receipt_overflow")
            return raw
        except subprocess.TimeoutExpired:
            raise BillingRefused("receipt_timeout") from None
        except (OSError, ValueError):
            raise BillingRefused("receipt_lookup_failed") from None


def _main():
    if sys.argv[1:] != ["--lookup"]:
        return 2
    try:
        request = json.loads(sys.stdin.buffer.read(8193))
        if not isinstance(request, list) or len(request) != 2:
            return 2
        credential, generation = request
        VercelGenerationClient(credential)
        _generation(generation)
        raw = _lookup_https(credential, generation)
        sys.stdout.buffer.write(b"200\n" + raw)
        return 0
    except BillingRefused as error:
        return 4 if str(error) == "receipt_pending" else 3
    except Exception:
        return 3


if __name__ == "__main__":
    sys.exit(_main())
