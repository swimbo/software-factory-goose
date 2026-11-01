"""Metadata-only broker RPC to the independently identified usage collector.

The collector reads authenticated immutable capture and settles the existing owner
journal. This transport creates no reservation, allowance, launch or billing fact.
Only Root bootstrap supplies service identities, frozen route, tariff and paths.
"""

import copy
import os

from factory_harness import canonical
from physical_usage import CaptureBinding, PhysicalUsageCollector
from protected_spending_control import (
    ControlRefused,
    PrivateSpendingClient,
    _digest,
    _integer,
    _keys,
    _micros,
    _rated_usd,
)

ATTEMPT_FIELDS = frozenset(
    ("attempt_id", "budget_owner", "route", "mode", "cost_basis", "tariff_sha256")
)
CALL_FIELDS = frozenset(
    (
        "call_id",
        "scope_sha256",
        "request_sha256",
        "sequence",
        "request_bytes",
        "output_tokens",
    )
)
RESPONSE_FIELDS = frozenset(
    ("call_id", "scope_sha256", "request_sha256", "physical_manifest_sha256")
)
RECEIPT_FIELDS = RESPONSE_FIELDS | frozenset(
    (
        "route_sha256",
        "billing_receipt_sha256",
        "usage_rated_microusd",
        "usage_rated_usd",
        "tariff_sha256",
        "audit_sha256",
        "source",
        "all_calls_complete",
    )
)


def require(ok, reason):
    if not ok:
        raise ControlRefused(reason)


def validate_request(body):
    require(_keys(body, ("attempt", "call", "response")), "invalid_settlement_request")
    attempt, call, response = body["attempt"], body["call"], body["response"]
    require(
        _keys(attempt, ATTEMPT_FIELDS)
        and _keys(call, CALL_FIELDS)
        and _keys(response, RESPONSE_FIELDS),
        "invalid_settlement_request",
    )
    require(
        attempt["mode"] in ("live", "rehearsal")
        and attempt["cost_basis"] == "audited_usage_rated"
        and _integer(call["sequence"], 0, 31)
        and _integer(call["request_bytes"], 1, 65536)
        and _integer(call["output_tokens"], 1, 16384)
        and all(
            response[k] == call[k]
            for k in ("call_id", "scope_sha256", "request_sha256")
        ),
        "invalid_settlement_request",
    )
    try:
        CaptureBinding(
            1,
            attempt["budget_owner"],
            attempt["attempt_id"],
            call["call_id"],
            call["scope_sha256"],
            attempt["route"],
            call["request_sha256"],
            attempt["tariff_sha256"],
            response["physical_manifest_sha256"],
        ).validate()
    except Exception:
        raise ControlRefused("invalid_settlement_request") from None
    return body


def settlement_request(attempt, call, response):
    require(
        type(attempt) is dict
        and ATTEMPT_FIELDS <= set(attempt)
        and type(call) is dict
        and _keys(call, CALL_FIELDS)
        and type(response) is dict
        and set(response) in (RESPONSE_FIELDS, RESPONSE_FIELDS | {"sse"}),
        "invalid_settlement_request",
    )
    # SSE and unrelated attempt fields stay within the broker. They are neither
    # serialized over the collector socket nor inputs to usage normalization.
    return validate_request(
        dict(
            attempt={k: copy.deepcopy(attempt[k]) for k in ATTEMPT_FIELDS},
            call=copy.deepcopy(call),
            response={k: copy.deepcopy(response[k]) for k in RESPONSE_FIELDS},
        )
    )


def validate_policy(body, owner, route, tariff, mode):
    require(
        body["attempt"]["budget_owner"] == owner
        and body["attempt"]["route"] == route
        and body["attempt"]["tariff_sha256"] == tariff
        and body["attempt"]["mode"] == mode,
        "settlement_binding_mismatch",
    )


def validate_receipt(value, body):
    require(_keys(value, RECEIPT_FIELDS), "settlement_outcome_unknown")
    attempt, response = body["attempt"], body["response"]
    require(
        all(value[k] == response[k] for k in RESPONSE_FIELDS)
        and value["route_sha256"] == attempt["route"]
        and value["tariff_sha256"] == attempt["tariff_sha256"]
        and _digest(value["billing_receipt_sha256"])
        and _digest(value["audit_sha256"])
        and _integer(value["usage_rated_microusd"], 0, 750000)
        and value["source"]
        == ("synthetic" if attempt["mode"] == "rehearsal" else "audited_usage_rated")
        and value["all_calls_complete"] is True,
        "settlement_outcome_unknown",
    )
    try:
        require(
            _micros(_rated_usd(value["usage_rated_usd"]))
            == value["usage_rated_microusd"],
            "settlement_outcome_unknown",
        )
    except Exception:
        raise ControlRefused("settlement_outcome_unknown") from None
    return copy.deepcopy(value)


class PrivateSettlementClient(PrivateSpendingClient):
    """Broker identity only. No direct journal or capture endpoint is exposed."""

    def __init__(
        self,
        path,
        *,
        collector_uid,
        broker_uid,
        worker_uid,
        owner,
        route_sha256,
        tariff_sha256,
        mode="live",
    ):
        require(
            len({0, collector_uid, broker_uid, worker_uid}) == 4
            and all(
                _integer(uid, 1, 2**31 - 1)
                for uid in (collector_uid, broker_uid, worker_uid)
            )
            and _digest(route_sha256)
            and _digest(tariff_sha256)
            and mode in ("live", "rehearsal"),
            "settlement_identity_invalid",
        )
        super().__init__(
            path, service_uid=collector_uid, broker_uid=broker_uid, owner=owner
        )
        self.route, self.tariff, self.mode = route_sha256, tariff_sha256, mode

    def __call__(self, *_):
        raise ControlRefused("settlement_method_denied")

    def settle(self, attempt, call, response):
        require(os.geteuid() == self.broker_uid, "settlement_role_denied")
        body = settlement_request(attempt, call, response)
        validate_policy(body, self.owner, self.route, self.tariff, self.mode)
        try:
            value = self._send(
                "settle", canonical(body).encode(), prefix="/settlement/"
            )
        except Exception:
            # Settlement may already be journaled. Never retry or manufacture a
            # receipt; the caller's existing unknown-dispatch fence remains binding.
            raise ControlRefused("settlement_outcome_unknown") from None
        return validate_receipt(value, body)


class ProtectedUsageSettlement:
    """Only an actual independent collector may construct this service backend."""

    def __init__(self, collector, *, broker_uid, worker_uid, route_sha256):
        require(
            type(collector) is PhysicalUsageCollector
            and os.geteuid() == collector.source.collector_uid
            and collector.source.collector_uid == collector.authority.collector_uid
            and collector.source.owner == collector.authority.owner
            and len(
                {
                    0,
                    broker_uid,
                    worker_uid,
                    collector.source.collector_uid,
                    collector.source.service_uid,
                    collector.authority.service_uid,
                }
            )
            == 6
            and all(
                _integer(uid, 1, 2**31 - 1)
                for uid in (
                    broker_uid,
                    worker_uid,
                    collector.source.collector_uid,
                    collector.source.service_uid,
                    collector.authority.service_uid,
                )
            )
            and _digest(route_sha256),
            "settlement_private_services_invalid",
        )
        self.collector, self.broker_uid = collector, broker_uid
        self.protected_uid = collector.source.collector_uid
        self.owner, self.route = collector.source.owner, route_sha256
        self.tariff, self.mode = collector.tariff_sha256, collector.mode

    def dispatch(self, uid, method, body):
        require(uid == self.broker_uid and method == "settle", "settlement_role_denied")
        validate_request(body)
        validate_policy(body, self.owner, self.route, self.tariff, self.mode)
        result = self.collector.settle(
            copy.deepcopy(body["attempt"]),
            copy.deepcopy(body["call"]),
            copy.deepcopy(body["response"]),
        )
        return validate_receipt(result, body)
