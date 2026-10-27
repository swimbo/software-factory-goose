# Claim lease state consistency

The claim journal now refuses renewal or completion unless the stored stage is `Leased` and the lease attempt matches the state's current attempt. A new claim also refuses inconsistent active/stage/attempt combinations, including after an apparent expiry. A duplicate completion must match the terminal stage produced by its receipt, in addition to the existing exact lease and receipt checks. Negative tests first demonstrated an inconsistent-stage renewal bypass; all 16 claim-journal unit tests passed after the fix. Exact duplicate completion remains idempotent in its valid resulting state.

This is a local state-invariant safeguard, not an intake-to-qualification binding, an authenticated deployment or proof of recovery from arbitrary corrupted historical state. Runtime integration, private ingress and isolation remain open.
