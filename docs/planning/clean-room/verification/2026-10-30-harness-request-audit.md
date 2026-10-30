# Phase 11A request-path audit — 2026-10-30

## Observed owning sources

- `clean-room/deployment/relay/nuc_goose_worker.py`: pinned Goose forwards bounded
  HTTP requests through a credential-free shim. Its MCP surface is fixed to
  `write_files`; the protected prompt is a root-owned file. No script tool exists
  in this worker. Model `auto` routing is imposed by the relay, not the worker.
- `clean-room/deployment/relay/nuc_relay_core.py`: initial request is verified
  against root-owned scope; continuation must equal the initial conversation plus
  the exact admitted assistant/tool messages. Argument whitespace is normalized
  only for the admitted writer tool. Each exchange begins a fence before transport;
  uncertain transport or writer outcomes retain `unknown`, not retryable success.
- `clean-room/deployment/relay/nuc_relay_stream.py`: complete bounded SSE parsing
  retains prompt/completion/total usage. Detailed cached-token fields are not
  retained, so cache usage in current records is unknown. Usage is not billed cost.
- `clean-room/crates/execution/src/tool_output.rs` and `mask.rs`: complete UTF-8
  assembly, hard limits, heuristic masking, and explicit refusal on partial,
  unsupported or oversized responses. These semantics must survive optimization.

## Consequences

Never insert new schemas, regenerate static prefixes or reorder existing signed/
fenced requests in transit. Progressive discovery and stable-prefix construction
are candidate request-builder responsibilities, reviewed before a new scope is
issued. Optional schema visibility is independent of execution authority.

`harness/observation` is a passive metadata collector for trusted future exchange
hooks; it does not rewrite or log raw requests. The new candidate session and C
host are deliberately absent from root-owned deployment manifests and launcher
allowlists. The existing `auto` route is preserved; no provider-specific temperature,
reasoning or prompt changes are inferred from the supplied report.

## Remaining evidence

Production registration requires a generalized but still exact-authority relay
contract, pinned-Goose MCP canary, bounded/cancellable broker transport and trusted
telemetry/evaluator collection. The fixed two-turn fixture cannot run the frozen
20-task suite. No measured cache hit rate, billed-cost reduction, live benchmark,
production admission, deployment or candidate promotion is claimed here.
