# Debate Transcript — Architecture (Clean-Room Software Factory)

Record of the adversarial consensus debate over `architecture.md`.

## Participants (5 personas)
1. Senior AI Agent Systems Engineer (agent loop, wall, qualifier)
2. Principal Systems Architect (plane boundaries, state ownership, integration)
3. Senior Backend Engineer (Rust) (subprocess contract, Restate replay, kill switch)
4. Principal Application Security Architect (isolation, credentials, gates)
5. FinOps / Cloud Cost Optimization Engineer (contrarian — cost, budget enforcement)

## Rounds
- **Round 1 (position papers)**: 5 independent critiques. Verdicts ranged "risky, not flawed" (AI, Systems, Rust) to "security theater at its most important seam" (Security) and "cost model is a hand-wave" (FinOps).
- **Moderator synthesis**: 5 consensus clusters, 12 contested decisions (7 HIGH), 6 blind spots.
- **Round 1 (responses)**: targeted convergence on the HIGH-impact items.

## Key positions and concessions

| Persona | Maintained | Conceded |
|---------|-----------|----------|
| AI Agent Systems | wall needs OS boundary; gate needs a real formula; model-independence; qualifier unspecified | C1 wording (adopted Seatbelt+uid); gate form (gave Clopper–Pearson formula, but see O2) |
| Systems Architect | Restate journal = source of truth; two binaries; non-replayed spawn; 90% gate is pre-filter not authority | "dual-ownership" → "dual-write" (outbox fixes); shared gateway covert channel (conceded to Security) |
| Rust Backend | typed Receipt; ctx.run + idempotency key; kill -pgid; env-by-identity | "does not execute agent code" (overstated → separate worker binary); "exit code + diff" phrasing (loose) |
| Security | uid+DAC boundary (not path/mount); git deploy-key spec; out-of-band brake key; scan-before-validate | model-independence (verdict must rest on human oracle, not another LLM); adopted kill -pgid as primitive |
| FinOps | hard cumulative budget cutoff; dollar ceiling not retry count; routing = hypothesis not fact | 15× → ~4× (withdrawn); accepted Restate/gateway topology with default-deny |

## Resolved (consensus) → see consensus-plan.md R1–R12
All 12 contested decisions resolved. The three-persona overlap (single-source-of-truth, OS-isolation-for-wall, hard-budget-cutoff) confirmed the highest-leverage fixes.

## Open items → consensus-plan.md O1–O6
- O1 serving backend (NEEDS_HUMAN_DECISION)
- O2 gate sample size (cost-bounded MVP resolution)
- O3 qualifier spec (follow-on doc)
- O4 operator auth + MFA + rotation
- O5 scenario authoring/coverage/drift
- O6 supply-chain (generator as attacker)

## Outcome
Consensus reached in one round (no further rounds needed). architecture.md updated with a `## Debate Outcomes` section pointing to R1–R12; consensus-plan.md is authoritative where they conflict.
