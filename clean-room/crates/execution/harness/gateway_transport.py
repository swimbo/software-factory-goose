"""Protected broker transport for gateway-owned one-use acquisition.

This is a private protocol client, not a live admission switch. The dedicated
gateway must acquire through the existing broker, execute with its typed Root
context, and acknowledge durable complete capture before returning this response.
Production ingress/composition and provider bounds remain separate prerequisites.
"""

import base64
import copy
import os
import time

from factory_harness import canonical
from gateway_custody import ProtectedGatewayAcquisitionAuthority, root_binding
from protected_spending_control import (
    ControlRefused,
    MAX_SSE,
    PrivateSpendingClient,
    SOURCE_FIELDS,
    _digest,
    _integer,
    _keys,
    binding_digest,
)


def require(value, reason):
    if not value:
        raise ControlRefused(reason)


class PrivateGatewayClient(PrivateSpendingClient):
    def __init__(self, path, *, gateway_uid, broker_uid, owner):
        require(len({0, gateway_uid, broker_uid}) == 3, "gateway_role_alias")
        super().__init__(
            path, service_uid=gateway_uid, broker_uid=broker_uid, owner=owner
        )

    def __call__(self, *_):
        raise ControlRefused("gateway_method_denied")

    def exchange(self, root, call, request, expires_at_ms):
        require(os.geteuid() == self.broker_uid, "gateway_broker_required")
        require(
            root_binding(root) == root and root["owner"] == self.owner,
            "gateway_binding_mismatch",
        )
        remaining = (expires_at_ms - time.time_ns() // 1000000) / 1000
        require(0 < remaining <= 180, "gateway_deadline_expired")
        raw = canonical(
            dict(binding=root, call=call, request=request, expires_at_ms=expires_at_ms)
        ).encode()
        try:
            value = self._send(
                "exchange",
                raw,
                prefix="/gateway/",
                request_limit=131072,
                response_limit=2 * MAX_SSE,
                timeout=remaining,
            )
            require(
                _keys(value, SOURCE_FIELDS)
                and all(
                    value[k] == call[k]
                    for k in ("call_id", "scope_sha256", "request_sha256")
                )
                and _digest(value["physical_manifest_sha256"])
                and isinstance(value["sse"], str)
                and time.time_ns() // 1000000 < expires_at_ms,
                "gateway_outcome_unknown",
            )
            result = copy.deepcopy(value)
            result["sse"] = base64.b64decode(value["sse"], validate=True)
            require(0 < len(result["sse"]) <= MAX_SSE, "gateway_output_overflow")
            return result
        except Exception:
            # The gateway may already have consumed begin; never retry this send.
            raise ControlRefused("gateway_outcome_unknown") from None


class ProtectedGatewayTransport:
    def __init__(
        self,
        journal,
        acquisition,
        client,
        *,
        route_sha256,
        tariff_sha256,
        mode,
        scope_client=None,
    ):
        from linux_runner import PrivateRootSupervisorClient

        require(
            type(journal) is PrivateSpendingClient
            and type(acquisition) is ProtectedGatewayAcquisitionAuthority
            and type(client) is PrivateGatewayClient
            and acquisition.journal is journal
            and acquisition.protected_uid == journal.broker_uid == client.broker_uid
            and acquisition.uid == client.service_uid
            and journal.owner == client.owner
            and _digest(route_sha256)
            and _digest(tariff_sha256)
            and mode in ("live", "rehearsal")
            and (mode != "live" or scope_client is not None)
            and (
                scope_client is None
                or type(scope_client) is PrivateRootSupervisorClient
                and scope_client.broker_uid == journal.broker_uid
                and scope_client.service_uid == 0
            )
            and os.geteuid() == journal.broker_uid,
            "gateway_private_services_invalid",
        )
        self.journal, self.acquisition, self.client = journal, acquisition, client
        self._scope_client = scope_client
        self.owner, self.route, self.tariff, self.mode = (
            journal.owner,
            route_sha256,
            tariff_sha256,
            mode,
        )

    def validate_control(self, config, journal):
        require(
            self.journal is journal
            and config.get("owner") == self.owner
            and config.get("route_sha256") == self.route
            and config.get("tariff_sha256") == self.tariff
            and config.get("cost_basis") == "audited_usage_rated"
            and config.get("mode") == self.mode,
            "gateway_control_binding_mismatch",
        )

    def exchange(self, *_):
        raise ControlRefused("gateway_reserved_dispatch_required")

    def exchange_reserved(self, attempt, grant, call, request):
        require(
            os.geteuid() == self.acquisition.protected_uid, "gateway_broker_required"
        )
        raw = canonical(request).encode()
        require(
            _keys(
                call,
                (
                    "call_id",
                    "scope_sha256",
                    "request_sha256",
                    "sequence",
                    "request_bytes",
                    "output_tokens",
                ),
            )
            and type(attempt) is dict
            and type(grant) is dict
            and attempt.get("budget_owner") == grant.get("owner") == self.owner
            and attempt.get("route") == grant.get("route_sha256") == self.route
            and attempt.get("tariff_sha256") == self.tariff
            and attempt.get("mode") == self.mode
            and attempt.get("cost_basis") == "audited_usage_rated"
            and grant.get("attempt_id") == attempt.get("attempt_id")
            and grant.get("scope_sha256") == call["scope_sha256"]
            and call["request_sha256"] == binding_digest(request)
            and call["request_bytes"] == len(raw)
            and call["output_tokens"] == request.get("max_tokens")
            and _integer(grant.get("expires_at_ms"), 1, 253402300799999),
            "gateway_binding_mismatch",
        )
        now = time.time_ns() // 1000000
        # No physical-call root may cross its lease, task deadline or reserved day.
        expiry = min(
            grant["expires_at_ms"], now + 180000, (now // 86400000 + 1) * 86400000
        )
        require(now < expiry, "gateway_deadline_expired")
        root = root_binding(
            dict(
                schema=1,
                owner=self.owner,
                attempt_id=attempt.get("attempt_id"),
                call_id=call["call_id"],
                scope_sha256=call["scope_sha256"],
                route_sha256=self.route,
                request_sha256=call["request_sha256"],
                tariff_sha256=self.tariff,
            )
        )
        scope_client = getattr(self, "_scope_client", None)
        require(
            self.mode != "live" or scope_client is not None, "gateway_scope_required"
        )
        if scope_client is None:
            self.acquisition.arm(root, copy.deepcopy(call))
        else:
            preimage = scope_client(
                "scope_preimage_v2",
                {"attempt": attempt, "scope_sha256": call["scope_sha256"]},
            )
            require(
                _keys(preimage, ("schema", "scope_sha256", "scope", "root_deadline_ms"))
                and preimage["schema"] == 2
                and type(preimage["schema"]) is int
                and preimage["scope_sha256"] == call["scope_sha256"]
                and type(preimage["scope"]) is dict,
                "gateway_scope_changed",
            )
            saved_attempt = copy.deepcopy(attempt)
            saved_call = copy.deepcopy(call)
            saved_scope = copy.deepcopy(preimage["scope"])
            root_deadline = preimage["root_deadline_ms"]
            journal = self.journal

            def verify_inflight():
                # No reservation or retry is created by this check. The gateway
                # must still be fenced if authority is lost after the check.
                if journal("verify_inflight", copy.deepcopy(saved_call)) is not True:
                    return False
                current = scope_client(
                    "scope_preimage_v2",
                    {
                        "attempt": copy.deepcopy(saved_attempt),
                        "scope_sha256": saved_call["scope_sha256"],
                    },
                )
                return (
                    _keys(
                        current, ("schema", "scope_sha256", "scope", "root_deadline_ms")
                    )
                    and type(current["schema"]) is int
                    and current["schema"] == 2
                    and current["scope_sha256"] == saved_call["scope_sha256"]
                    and type(current["scope"]) is dict
                    and canonical(current["scope"]) == canonical(saved_scope)
                    and type(current["root_deadline_ms"]) is int
                    and current["root_deadline_ms"] >= root_deadline
                    and time.time_ns() // 1000000 < min(root_deadline, expiry)
                )

            self.acquisition.arm_v2(
                root,
                copy.deepcopy(call),
                saved_scope,
                root_deadline,
                verify=verify_inflight,
            )
        return self.client.exchange(
            root, copy.deepcopy(call), copy.deepcopy(request), expiry
        )
