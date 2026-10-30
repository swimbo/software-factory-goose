# NUC administrative boundary — authorized 2026-10-29

User explicitly authorized scoped NUC host administration through existing Docker permission, continuing from a33c9db. The administrative mechanism decision below is resolved; it does not authorize shared-service restart, host reboot, silent human login-key issuance or candidate promotion. Preserve existing services and data.

## Observed access

`bo` is UID1000 and belongs to the Docker group. Noninteractive `sudo` is unavailable. There are no host passwd entries for the fixture UIDs1001/1002. Existing Docker, Hermes dashboard/gateway and Stapled resources must be preserved. Docker live restore is disabled; changing or restarting the shared daemon is not authorized by this proposal.

The current experiment proves a live model-generated, isolated, hash-bound candidate. It does not provision the separate local operator account selected in O4, establish an independent stop authority during Docker failure, or connect the production factory pipeline.

## Proposed administrative scope

Subject to a reviewed implementation, establish only factory-owned resources:

- Separate local service, worker, evaluator and operator identities, with checked unused UID/GID assignments. No existing account, group membership, SSH key or sudo policy is changed. Do not silently reuse the fixture numeric UIDs or authorize a human login key.
- A narrowly scoped root-owned supervisor outside Docker, authenticated private Unix ingress, an independently usable operator stop channel, and a persistent factory-only cgroup hierarchy. Its catalogue and admission-closure records bind exact task identities; arbitrary PIDs, paths, commands or shared containers cannot be selected by a worker.
- Pinned reviewed binaries under `/usr/local/libexec/software-factory-goose/`, units prefixed `software-factory-goose-`, and root-owned state under `/var/lib/software-factory-goose/` with restrictive permissions. Do not enable admission until provenance, identity, late-launch closure, owner-loss and recovery checks pass.
- Preserve all prior unknown fences and the retained inert created-container reservation. Never remove/start/rename it as part of installation.

Installation must first produce an exact file/account/unit inventory and rollback procedure, check name/UID/path collisions and free space, and refuse partial or ambiguous prior installation. Starting the new supervisor must not restart Docker, Bifrost, Hermes or Stapled. Host reboot or shared daemon-failure testing requires a separately reviewed maintenance window or isolated equivalent; it is not implied here.

## Privilege mechanism — resolved by user authorization

Preferred: an operator-provided administrative session or narrowly approved installer invocation. The existing `bo` Docker permission is also capable of granting host-root authority, but the fixture's permission to create isolated workers does not by itself approve using that power to modify the host OS. Such use requires an explicit choice before implementation/deployment of this boundary.

This document is a scope proposal, not an executable installer or completed deployment approval. No host-root access, host accounts, units or shared-service configuration were changed in preparing it. No password or private key should be sent in chat.

## 2026-10-29 execution boundary

The first owned root bridge tests verified that host PID namespace plus only SYS_CHROOT/DAC_OVERRIDE, a fixed reviewed inline program, host-root bind, isolated Python and no container network can query the real system manager. A separate PID namespace failed with ENODATA; capability-name normalization was required before any start. Only bridge operations with exact full-ID/config/intents and ownership verification are allowed. No broad privileged container or new host capability is inferred. A narrowly necessary additional capability for a specific install operation must be reviewed and tested before use.

The first frozen late-start canary was retained as unknown, then reconciled using exact-version Moby start/remove locking and successful non-force exact-ID removal, same-inode frozen/empty observation and scoped manager cleanup. This is not production containment or host/daemon-loss certification. See verification/2026-10-29-nuc-late-start-freeze-canary.md.

Existing bo UID1000 may serve as the human operator account after distinct nonroot service/worker/evaluator/journal roles are provisioned. This preserves its existing SSH authentication and grants no new login key, group membership or sudo permission. Its existing host-administrative Docker power remains trusted; no design can claim protection from that administrator. Independent stop availability and protection against a stolen operator bearer are separate requirements.
