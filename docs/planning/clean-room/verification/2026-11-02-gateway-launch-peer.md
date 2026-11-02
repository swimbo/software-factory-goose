# Launch-bound gateway peer verification

Date: 2026-11-02. Source-only checkpoint; no production admission or paid calls.

The prior peer check accepted any qualifying executable in the attempt cgroup. It did not require the process to be the child Root prepared and released. The new check requires schema 4 and protected, mutually consistent preparation, attachment, namespace, release-intent and release records bound to the current grant, scope, UID, PID and start ticks. It reuses non-reaping child and namespace inspection before the existing executable/cgroup check. Existing current-authority and guard checks remain in force.

## Evidence

- The missing-launch-record regression failed before the implementation and passes afterward.
- Native x86-64 NUC replay used actual Root preparation, namespace mapping, cgroup attachment and release. The released parent passed; a same-binary descendant passed the legacy attribute check and failed the launch-bound check. Verification did not alter any launch records.
- After fencing and fixture retirement, an independent SSH check confirmed the exact gateway PID, attempt cgroup and fixture container absent. The fixture also verified its socket absent.
- Unit tests reject absent/malformed records, valid-shaped stale attachment/namespace scopes, coherent but wrong release hashes, changed PID/start ticks, failed namespace inspection, unsupported schema and lost/changed guard.
- Configured harness: 278 run, 271 passed, seven skipped. Focused peer suite: 31 run, 30 passed, one skipped. Ruff passed.
- Six-lens review completed with no actionable findings (`gateway-launch-peer-213wrfnb`). The review's receipt-binding test gap was addressed afterward and the suite rerun. Claude review transport failed before egress; the adversarial lens used an in-process fallback.

[Native result and source hashes](2026-11-02-gateway-launch-peer.json).

## Limits and remaining integration

The native authority, guard and socket-binding seams are synthetic. The fixture calls the launch-bound verifier and kernel helpers directly; it does not qualify the complete production authenticated broker RPC. These checks establish point-in-time identity, not lifetime descriptor custody or an egress fence. Production constructor/retained route integration, handed-socket cleanup, provider charge bounds and remaining native failure qualification stay open. Candidate disabled; live benchmark remains 0/120.
