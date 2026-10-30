# Bounded registry append and owned SDK restart — design for review

This is not authorization to update the host or launch another generation. The
current registry has one active entry and preserves the three compiled historical
entries; the failed generation and its durable reservation remain closed. Use one
root-provisioned registry runtime and one durable journal, rather than a new
sidecar for each generation.

A root-owned coordinator should take a persistent, exclusive registry-upgrade
lock shared by all grant admission and catalog provisioning. The currently
installed grant path does not participate in such a lock, so this is a missing
implementation prerequisite. During transition the protected registry grant
socket must be closed to new work, and the coordinator must prove all registered
launch producers terminal with no systemd jobs and all prior create/start
operations either reconciled or durably quarantined. Stopping the SDK cannot
clear reservations or substitute for independently closing/freeze-killing any
running workload.

Under the lock, mint a new root-owned immutable config/evidence pair for a fresh
intent, task and generation. Validate fixed ownership, no-follow path and ACL,
single-link regular files, size bounds, canonical identifiers, root recipe and
qualified fingerprint. The new manifest must copy every existing entry exactly,
append exactly one unique entry, select only that new intent, retain the compiled
historical pins, and remain within the current 16-entry limit. It must never
modify the previously consumed journal claim, grant, catalog or closure. Fsync
exclusive temporary files, then publish the immutable pair before atomically
replacing and fsyncing the registry manifest. Persist the old manifest, intent,
new digests and an explicit transition receipt. Any incomplete or ambiguous
step denies admission and retains both generations for recovery.

Restart only the exact reviewed factory-owned registry service and its socket
units, with no shared journal, Docker, Hermes, Bifrost or Stapled restart. Before
restart, durably record the exact old service identity and manifest digests;
validate unit hashes, aliases, drop-ins, no pending jobs, and socket ownership.
After restart, require the existing Rust loader to revalidate every entry and
fingerprint, register the fixed owned SDK revision, and prove journal replay of
old reservations without reassignment. Mint a new root process attestation
binding the new registry manifest, service PID/start time, socket/cgroup identity,
boot and existing namespace anchors; a prior process attestation is invalid.
Run native cap-empty readiness and authenticated brake checks before allowing a
new claim. If registration, restart, attestation or journal replay is unknown,
keep the admission gate closed and never retry a claim automatically.

Before implementation acceptance, test normal append plus changed/deleted prior
entry, duplicate identifiers, 16-entry exhaustion, journal replay, crash at each
manifest publication stage, lost restart acknowledgement, stale PID/socket
attestation and racing grant admission. Verify that a failed transition cannot
admit either generation and that exact owned recovery preserves prior records.
The bounded 16-entry policy needs an explicit reviewed archival/compaction design
before it can support indefinite operation; silent eviction is forbidden.
