"""Collector-only audited usage closure; no inference, refunds or new allowance.

The protected supervisor supplies complete physical dispatches and authenticated
non-dispatch evidence. Root scopes bind the tariff. Evidence IDs derive from
stable protected dispatch IDs, never timestamps or model-supplied generation IDs.
"""

from usage_rating import Manifest, UsageRatedCollector, UsageRatingRefused
from billing_receipts import _digest, _name
from billing_spending import _hash


def collect_usage_for_spending(
    manifest,
    *,
    collector,
    authority,
    call_id,
    scope_sha256,
    route_sha256,
    request_sha256,
    expected_components,
    component_calls,
    absent_components,
):
    if not isinstance(collector, UsageRatedCollector) or type(manifest) is not Manifest:
        raise UsageRatingRefused("invalid_usage_collector")
    frozen = collector.validate_manifest(manifest)
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
        raise UsageRatingRefused("spending_binding_mismatch")
    if (
        set(component_calls) & set(absent_components)
        or set(component_calls) | set(absent_components) != set(expected_components)
        or any(not _digest(v) for v in absent_components.values())
    ):
        raise UsageRatingRefused("incomplete_component_dispositions")
    ids = []
    for calls in component_calls.values():
        if type(calls) is not tuple or not calls or any(not _name(v) for v in calls):
            raise UsageRatingRefused("invalid_component_dispositions")
        ids.extend(calls)
    if len(ids) != len(set(ids)) or set(ids) != set(frozen.expected_call_ids):
        raise UsageRatingRefused("incomplete_component_dispositions")
    binding = _hash(
        {
            "collection_manifest_sha256": frozen.sha256(),
            "tariff_sha256": collector.tariff.sha256(),
            "call_id": call_id,
            "scope_sha256": scope_sha256,
            "component_calls": component_calls,
            "absent_components": absent_components,
        }
    )
    evidence_ids = sorted(
        "usage_" + _hash({"provider": c.provider, "call_id": c.call_id})
        for c in frozen.calls
    )
    common = dict(
        call_id=call_id,
        scope_sha256=scope_sha256,
        request_sha256=request_sha256,
        manifest_sha256=binding,
        generation_ids=evidence_ids,
    )

    def durable(method, body):
        try:
            if authority(method, body) is not None:
                raise UsageRatingRefused("authority_unavailable")
        except Exception:
            raise UsageRatingRefused("authority_unavailable") from None

    durable("claim_receipts", common)
    report = collector.collect(frozen)
    by_call = dict(zip(frozen.expected_call_ids, report["receipts"], strict=True))
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
            "usage_rating": {
                "tariff_sha256": report["tariff_sha256"],
                "audit_sha256": report["audit_sha256"],
                "usage_rated_microusd": report["usage_rated_microusd"],
            },
        },
    )
    return report | {"spending_manifest_sha256": binding}
