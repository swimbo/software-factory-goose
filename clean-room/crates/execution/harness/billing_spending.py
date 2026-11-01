"""Trusted collector-to-journal adapter, never registered as a worker tool.

authority(method,body) must be the fixed owner's authenticated private Restate
client, with bounded/cancellable I/O. Only claim_receipts and complete are used.
The supervisor verifies route, request, closed dispatch journal and component
dispositions before calling this adapter. Digests alone do not authenticate them.
Neither this adapter nor the collector dispatches inference or refunds reserves.
"""

import hashlib
import json

from billing_receipts import (
    BillingRefused,
    Manifest,
    ReceiptCollector,
    _digest,
    _name,
    asdict_manifest,
    freeze_manifest,
)


def _hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def collect_for_spending(
    manifest,
    *,
    authority,
    client,
    call_id,
    scope_sha256,
    route_sha256,
    request_sha256,
    expected_components,
    component_calls,
    absent_components,
):
    """Settle one dispatched call through its SAME task/daily spending journal.

    component_calls maps reviewed component IDs to every physical dispatch ID.
    absent_components maps uninvoked alternatives to authenticated journal closure
    evidence; absence from logs is insufficient. The private supervisor supplies
    both maps, never the model. All physical receipts must be used exactly once.
    Unknown, unsupported or partially collected costs leave the call Unknown.
    """
    if not isinstance(manifest, Manifest):
        raise BillingRefused("invalid_manifest")
    frozen = freeze_manifest(**asdict_manifest(manifest))
    if not (
        callable(authority)
        and _name(call_id)
        and _digest(scope_sha256)
        and route_sha256 == frozen.route_sha256
        and request_sha256 == frozen.request_sha256
        and type(expected_components) is tuple
        and 1 <= len(expected_components) <= 32
        and all(_name(v) for v in expected_components)
        and len(set(expected_components)) == len(expected_components)
        and type(component_calls) is dict
        and type(absent_components) is dict
        and len(frozen.calls) <= 32
    ):
        raise BillingRefused("spending_binding_mismatch")
    if (
        set(component_calls) & set(absent_components)
        or set(component_calls) | set(absent_components) != set(expected_components)
        or any(not _digest(v) for v in absent_components.values())
    ):
        raise BillingRefused("incomplete_component_dispositions")
    ids = []
    for calls in component_calls.values():
        if type(calls) is not tuple or not calls or any(not _name(v) for v in calls):
            raise BillingRefused("invalid_component_dispositions")
        ids.extend(calls)
    if len(ids) != len(set(ids)) or set(ids) != set(frozen.expected_call_ids):
        raise BillingRefused("incomplete_component_dispositions")
    collection_sha256 = frozen.sha256()
    spending_manifest_sha256 = _hash(
        {
            "collection_manifest_sha256": collection_sha256,
            "call_id": call_id,
            "scope_sha256": scope_sha256,
            "component_calls": component_calls,
            "absent_components": absent_components,
        }
    )
    generation_ids = sorted(c.generation_id for c in frozen.calls)
    common = {
        "call_id": call_id,
        "scope_sha256": scope_sha256,
        "request_sha256": request_sha256,
        "manifest_sha256": spending_manifest_sha256,
        "generation_ids": generation_ids,
    }

    def durable(method, body):
        try:
            if authority(method, body) is not None:
                raise BillingRefused("authority_unavailable")
        except Exception:
            # A lost acknowledgement may follow a journal commit. Do not infer
            # rollback, release a reservation or initiate another provider call.
            raise BillingRefused("authority_unavailable") from None

    def claim(generations, binding):
        if binding != collection_sha256 or sorted(generations) != generation_ids:
            raise BillingRefused("spending_binding_mismatch")
        durable("claim_receipts", common)

    result = ReceiptCollector(client, claim).collect(frozen)
    by_call = dict(zip(frozen.expected_call_ids, result["receipts"], strict=True))
    components = {
        name: _hash({"dispatched": [by_call[c] for c in calls]})
        for name, calls in component_calls.items()
    }
    components.update(
        {
            name: _hash({"not_dispatched": evidence})
            for name, evidence in absent_components.items()
        }
    )
    durable(
        "complete",
        common
        | {
            "route_sha256": route_sha256,
            "components": components,
            "billed_microusd": result["billed_microusd"],
        },
    )
    return result | {"spending_manifest_sha256": spending_manifest_sha256}
