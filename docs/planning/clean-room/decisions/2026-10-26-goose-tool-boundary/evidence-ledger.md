# Evidence ledger — Goose tool boundary

Decision: select a verifiable tool and output boundary, and truthful completion evidence, without changing the locked Goose architecture. Research sources and exact pinned links are in `research-harness.md`, `research-security.md`, and `research-operations.md`.

Verified at pinned v1.49.0: JSON completion can follow errors/cancellation; hooks are optional, can be bypassed by subagents, and cannot reliably replace output. Fresh no-profile extension restrictions are plausible, but resume restores prior extensions first and project plugins may still load. Tool-result paths include notifications, errors, structured data and other content, not just shell stdout. Cancellation is not proof of process termination. Cost and assistant-message counts do not establish total spend.

The current upstream release has a narrower terminal error change, but its full security and cost boundary is unverified. Restricted factory-owned MCP, a pinned patch/library integration and a newer release each require tests; none is established as a complete solution. R13's coverage of shell descendants and OS backstop needs explicit evaluation.

Evidence grade: **ADEQUATE for a bounded offline restricted-tool spike; INSUFFICIENT for activation or final architecture selection.** Require a real pinned binary and recording local model endpoint; positive controls; forged/unadvertised calls; plugin/resume/subagent bypass attempts; output variants and split secrets; failure/cancellation plus process reaping; and authoritative cost/revision reconciliation. Keep worker disabled until these pass and independent identity/network/budget gates are proven.
