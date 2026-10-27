# Decision brief: distinct-account OS supervision

**Status: three-reviewer research completed; evidence insufficient for a production selection.** See `2026-10-27-os-supervision-boundary/evidence-ledger.md` and `spike-plan.md`. No option has been selected or provisioned.

The Phase 9 worker must run under a distinct identity and an independent brake must stop its complete process family even if the worker or control plane hangs. The current macOS same-UID broker fixture owns and reaps its children and stops tested groups, but an unprivileged process cannot both assume arbitrary UIDs and signal children after they change identity. Process groups alone do not contain descendants that escape them. See `../verification/2026-10-27-watchdog-os-authority-review.md` and the broker lifecycle evidence.

## Decision questions

1. What minimal OS authority should own approved process creation, credential transition, containment, termination and reaping? Compare a small privileged supervisor behind a nonroot authenticated frontend with an OS service manager or another evidence-backed mechanism.
2. How will the independent brake authenticate and remain available during control-plane, database, worker and supervisor failures, without exposing launch authority to the model?
3. How will the system prevent executable/spec substitution, contain escaped descendants, avoid PID reuse, and recover safely after a supervisor crash or ambiguous acknowledgement?
4. What disposable distinct-account tests and recovery evidence are necessary before any production activation?

## Constraints and evidence

- User selected separate local operator account and action-bound approval, with no MFA claim. Preserve independent stop-only authority.
- No user accounts, privileged service, credentials or production listeners have been created. Do not change existing services or accounts for a fixture.
- The launch publisher must bind exact executable, arguments, environment and identity to authoritative claim, lease, deadline and policy; the model cannot submit arbitrary commands or PIDs.
- Current group and same-UID canaries demonstrate only their tested boundary. The full Goose/tool policy, Bifrost budget, holdout isolation and INT-LOOP gates remain open.
- Scope the review to the supported macOS deployment first, and state portability and recovery limits explicitly. No choice may claim a security property absent a reproducible negative control.

## Acceptance

Record evidence, options and dissent; select only a design whose authority and failure modes can be verified with disposable resources. Identify decisions requiring user input. A review outcome does not authorize account creation, production activation or deployment.
