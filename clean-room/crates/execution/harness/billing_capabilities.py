"""Read-only reviewed billing-source coverage; this is not inference authority.

This document and live-observation review records what a collector can establish, rather than
inventing a billing endpoint or treating an account balance as a request receipt.
The protected supervisor must separately bind actual route/configuration, closed
dispatch manifests, credential ownership and enforceable all-path price bounds.
No credential is accepted, no API is called, and no budget or route is changed.
"""

from dataclasses import dataclass

from billing_receipts import _digest, _name


@dataclass(frozen=True)
class BillablePath:
    id: str
    provider: str
    model: str
    operation: str


def factory_paths():
    """Reviewed eligible set; actual protected route digest must still be supplied."""
    return (
        BillablePath(
            "semantic-embedding",
            "vercel-classifier",
            "openai/text-embedding-3-small",
            "embedding",
        ),
        BillablePath(
            "llm-classifier", "vercel-classifier", "openai/gpt-6-luna", "chat"
        ),
        BillablePath(
            "answer-flash", "ollama-cloud", "deepseek-v4.1-flash:1017", "chat"
        ),
        BillablePath("answer-pro", "ollama-cloud", "deepseek-v4-pro:0813", "chat"),
    )


def _evidence():
    return {
        "ollama": {
            "source": "https://raw.githubusercontent.com/ollama/ollama/main/docs/openapi.yaml",
            "reviewed_schema_sha256": "d8e08be41dd858c933c32bef5ee8d0c5faf7d7462069a49b368731cfbceaab03",
            "documented_metadata_paths": ["/api/usage", "/api/balance"],
            "usage_filters": ["range", "scope", "group_by=model"],
            "public_api_attribution": "account_or_team_time_buckets",
            "account_request_costs_observed": True,
            "response_to_billing_id_verified": False,
            "account_cost_source": "https://ollama.com/blog/transparent-pricing",
            "request_billing_filter": None,
            "key_billing_filter": None,
            "documented_settlement_watermark": None,
            "new_key_is_account_isolation": False,
        },
        "vercel": {
            "source": "https://vercel.com/docs/ai-gateway/sdks-and-apis/rest-api",
            "chat_receipt": "GET https://ai-gateway.vercel.sh/v1/generation?id=gen_<ulid>",
            "paid_amount": "non-BYOK total_cost/gateway_cost/usage balance debit",
            "embedding_generation_receipt_verified": True,
            "embedding_dispatch_id_capture_verified": False,
            "embedding_lookup_evidence": "2026-10-30-harness-live-admission-audit.json",
        },
    }


def assess_receipt_sources(route_sha256, paths):
    """Check reviewed source coverage only, never authorize a live invocation.

    The caller supplies immutable trusted eligible paths from its exact route
    snapshot, including hidden classifier/fallback/retry outcomes. A complete
    result here is not proof that the deployed gateway captures every receipt.
    Dedicated-account assertions or catalog prices cannot override this review.
    """
    result = {
        "schema": 1,
        "reviewed_on": "2026-10-30",
        "route_sha256": route_sha256 if _digest(route_sha256) else None,
        "documented_per_request_coverage": False,
        "allows_live_inference": False,
        "paths": [],
        "blockers": [],
        "required_actual_evidence": [
            "authenticated_complete_dispatch_manifest",
            "correlated_provider_recorded_receipts",
            "reviewed_enforceable_all_path_charge_bounds",
        ],
        "evidence": _evidence(),
    }
    if (
        not _digest(route_sha256)
        or type(paths) is not tuple
        or not 1 <= len(paths) <= 32
        or any(not isinstance(p, BillablePath) or not _name(p.id) for p in paths)
        or len({p.id for p in paths}) != len(paths)
    ):
        result["blockers"].append({"id": None, "reason": "invalid_billing_scope"})
        return result
    reviewed = {(p.provider, p.model, p.operation) for p in factory_paths()}
    for path in paths:
        reason, endpoint = None, None
        # Exact known bindings only: an unknown model cannot inherit a provider's
        # documented behavior or substitute a different route's cost evidence.
        binding = (path.provider, path.model, path.operation)
        if not all(isinstance(v, str) for v in binding) or binding not in reviewed:
            reason = "unreviewed_model_binding"
        elif path.provider == "ollama-cloud":
            reason = "request_billing_correlation_unverified"
        elif path.operation == "embedding":
            endpoint = "https://ai-gateway.vercel.sh/v1/generation"
            reason = "embedding_generation_capture_unverified"
        else:
            endpoint = "https://ai-gateway.vercel.sh/v1/generation"
        result["paths"].append(
            {
                "id": path.id,
                "documented_per_request_receipt": reason is None,
                "receipt_endpoint": endpoint,
            }
        )
        if reason is not None:
            result["blockers"].append({"id": path.id, "reason": reason})
    result["documented_per_request_coverage"] = not result["blockers"]
    return result
