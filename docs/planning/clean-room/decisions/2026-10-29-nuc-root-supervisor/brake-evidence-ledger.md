# Brake caller amendment evidence ledger

All three research briefs and positions are dated 2026-10-29. Primary source links are retained in those artifacts.

| Claim | Evidence | Limit |
|---|---|---|
| Existing strict policy excludes ordinary operator | watchdog/src/lib.rs BrakePolicy::new; three positions | Current frontend draft violates intended usage; blocked |
| bo is operator distinct from provisioned services | installed identity receipt; O4 post-debate selection | bo Docker access is trusted root; no full-account compromise claim |
| Independent stop credential and availability required | R9; O4; three positions | Separate file alone does not prove agent isolation |
| A adds privileged executable but no human presence | execve/setgroups/setresuid primary references in briefs | Could retain stronger distinct caller contract if required |
| B can meet scoped bearer-theft boundary | all three positions now recommend conditional B | Requires explicit new policy and live identity, key and outage checks |
| C has unproven authorization/availability surface | systemd/polkit primary references | Not selected |

No positive production brake result or private-runtime deployment is implied by agreement.
